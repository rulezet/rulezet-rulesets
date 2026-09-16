rule sig_20161207_26dfed4844e84523a521a915a8723929 {
  meta:
    description = "datamaliciousorder - file 20161207_26dfed4844e84523a521a915a8723929.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "751d46baff3745a78e60e6934bb6926e5ac4cfc4eed7f88c4abfd454a385b2e5"

  strings:
    $s1 = "var vGh0 = new Function(\"vKc1\", '{var vSXk3 = new Date();vSXk3[\"setUTCFullYear\"](\"2003\");if (vSXk3.getUTCFullYear().toStri" ascii
    $s2 = "var vGh0 = new Function(\"vKc1\", '{var vSXk3 = new Date();vSXk3[\"setUTCFullYear\"](\"2003\");if (vSXk3.getUTCFullYear().toStri" ascii
    $s3 = "var vKb9 = new Function(\"vKc1\", '{return vKc1.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " == \"2003\") {var vBz8 = vKc1.split(\"###\"); return vBz8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}