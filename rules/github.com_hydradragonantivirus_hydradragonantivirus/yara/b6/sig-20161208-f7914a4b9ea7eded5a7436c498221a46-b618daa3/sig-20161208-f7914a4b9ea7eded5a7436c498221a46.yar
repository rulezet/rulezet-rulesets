rule sig_20161208_f7914a4b9ea7eded5a7436c498221a46 {
  meta:
    description = "datamaliciousorder - file 20161208_f7914a4b9ea7eded5a7436c498221a46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ecfeb06b878c600b27d5a322731d55ea3508ddd446d61ba7b2e8551061dc926"

  strings:
    $s1 = " = new Date();vMd5[\"setUTC\"+\"FullYear\"](\"2003\");if (vMd5.getUTCFullYear().toString(10) == \"2003\") {var vGm9 = vAYu0.spli" ascii
    $s2 = "var vIIn8 = new Function(\"vAYu0\", '{return vAYu0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBc6 = new Function(\"vAY" ascii
    $s3 = "var vIIn8 = new Function(\"vAYu0\", '{return vAYu0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBc6 = new Function(\"vAY" ascii
    $s4 = "); return vGm9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}