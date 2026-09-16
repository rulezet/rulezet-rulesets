rule sig_20161207_d683624f7684e98387d384a5ed8df35c {
  meta:
    description = "datamaliciousorder - file 20161207_d683624f7684e98387d384a5ed8df35c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c48832f361ee9fa239bca6c6566716c644eac9fd528bd7e3cd4055e9a79b6da2"

  strings:
    $s1 = " new Date();vXj0[\"setUTCFullYear\"](\"2003\");if (vXj0.getUTCFullYear().toString(10) == \"2003\") {var vYIh7 = vKg0.split(\"###" ascii
    $s2 = "var vLYu9 = new Function(\"vKg0\", '{return vKg0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXEd0 = new Function(\"vKg0" ascii
    $s3 = "var vLYu9 = new Function(\"vKg0\", '{return vKg0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXEd0 = new Function(\"vKg0" ascii
    $s4 = "turn vYIh7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}