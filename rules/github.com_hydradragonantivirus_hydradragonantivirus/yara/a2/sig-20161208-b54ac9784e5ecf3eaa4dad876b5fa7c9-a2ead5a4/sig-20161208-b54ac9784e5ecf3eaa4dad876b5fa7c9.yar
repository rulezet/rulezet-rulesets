rule sig_20161208_b54ac9784e5ecf3eaa4dad876b5fa7c9 {
  meta:
    description = "datamaliciousorder - file 20161208_b54ac9784e5ecf3eaa4dad876b5fa7c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "454f6c4a343eb5557ec0efe1487e26f117629606cba4d099cf527faf20c29910"

  strings:
    $s1 = "var vYRz3 = new Function(\"vRe8\", '{return vRe8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEPe1 = new Function(\"vRe8" ascii
    $s2 = " new Date();vFw6[\"setUTC\"+\"FullYear\"](\"2003\");if (vFw6.getUTCFullYear().toString(10) == \"2003\") {var vELz9 = vRe8.split(" ascii
    $s3 = "var vYRz3 = new Function(\"vRe8\", '{return vRe8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEPe1 = new Function(\"vRe8" ascii
    $s4 = " return vELz9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}