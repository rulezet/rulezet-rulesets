rule sig_20161207_aa68908288f58444c94ed820e853a8b1 {
  meta:
    description = "datamaliciousorder - file 20161207_aa68908288f58444c94ed820e853a8b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2a42bbc005ee44863b69ce4e5f9c08d450ef7b671047e3138b94c14eec55a8f"

  strings:
    $s1 = "var vJu6 = new Function(\"vMk6\", '{var vIr5 = new Date();vIr5[\"setUTCFullYear\"](\"2003\");if (vIr5.getUTCFullYear().toString(" ascii
    $s2 = "var vJu6 = new Function(\"vMk6\", '{var vIr5 = new Date();vIr5[\"setUTCFullYear\"](\"2003\");if (vIr5.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vZVh8 = vMk6.split(\"###\"); return vZVh8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vWRr3 = new Function(\"vMk6\", '{return vMk6.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}