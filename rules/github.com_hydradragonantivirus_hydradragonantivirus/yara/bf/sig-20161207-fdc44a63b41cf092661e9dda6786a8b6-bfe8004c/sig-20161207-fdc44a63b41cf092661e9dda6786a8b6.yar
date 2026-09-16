rule sig_20161207_fdc44a63b41cf092661e9dda6786a8b6 {
  meta:
    description = "datamaliciousorder - file 20161207_fdc44a63b41cf092661e9dda6786a8b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b42e67e787947ae6ff6f2687792ffb601ee6cf31a9abf735b17402f4c3415392"

  strings:
    $s1 = " new Date();vJKk7[\"setUTCFullYear\"](\"2003\");if (vJKk7.getUTCFullYear().toString(10) == \"2003\") {var vPy9 = vLw8.split(\"##" ascii
    $s2 = "var vAr0 = new Function(\"vLw8\", '{return vLw8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKQg7 = new Function(\"vLw8" ascii
    $s3 = "var vAr0 = new Function(\"vLw8\", '{return vLw8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKQg7 = new Function(\"vLw8" ascii
    $s4 = "eturn vPy9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}