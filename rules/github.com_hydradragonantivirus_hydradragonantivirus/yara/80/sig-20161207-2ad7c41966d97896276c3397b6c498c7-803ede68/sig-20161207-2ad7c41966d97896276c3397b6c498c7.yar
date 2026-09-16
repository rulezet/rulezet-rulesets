rule sig_20161207_2ad7c41966d97896276c3397b6c498c7 {
  meta:
    description = "datamaliciousorder - file 20161207_2ad7c41966d97896276c3397b6c498c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16a3cbcdd0c3afbac9e8a55c6665484897dc9d479f8454d2fbd7bb7fa52f29ec"

  strings:
    $s1 = "var vIGa0 = new Function(\"vWw4\", '{return vWw4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJu4 = new Function(\"vWw4" ascii
    $s2 = " new Date();vVMp8[\"setUTCFullYear\"](\"2003\");if (vVMp8.getUTCFullYear().toString(10) == \"2003\") {var vBUl8 = vWw4.split(\"#" ascii
    $s3 = "return vBUl8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vIGa0 = new Function(\"vWw4\", '{return vWw4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJu4 = new Function(\"vWw4" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}