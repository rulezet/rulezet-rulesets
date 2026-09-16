rule sig_20161207_ee0aef7273862cd1ebda812d74efbbc9 {
  meta:
    description = "datamaliciousorder - file 20161207_ee0aef7273862cd1ebda812d74efbbc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0aa36169e5ed41ae82691b5a3d1e6a81b610ac4cd3497c5aa24531ef6fc9c8ff"

  strings:
    $s1 = "var vLg7 = new Function(\"vEIk5\", '{var vKFh5 = new Date();vKFh5[\"setUTCFullYear\"](\"2003\");if (vKFh5.getUTCFullYear().toStr" ascii
    $s2 = "var vLg7 = new Function(\"vEIk5\", '{var vKFh5 = new Date();vKFh5[\"setUTCFullYear\"](\"2003\");if (vKFh5.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vTd9 = vEIk5.split(\"###\"); return vTd9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vWp9 = new Function(\"vEIk5\", '{return vEIk5.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}