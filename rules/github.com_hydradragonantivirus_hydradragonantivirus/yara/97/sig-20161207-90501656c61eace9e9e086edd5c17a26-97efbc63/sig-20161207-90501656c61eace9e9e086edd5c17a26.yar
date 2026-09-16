rule sig_20161207_90501656c61eace9e9e086edd5c17a26 {
  meta:
    description = "datamaliciousorder - file 20161207_90501656c61eace9e9e086edd5c17a26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e8bb3bc954c0fbf78093e25ada49d634e5b48009111b6cbb95b14f240eb04f5"

  strings:
    $s1 = "var vSq4 = new Function(\"vQd5\", '{var vEd9 = new Date();vEd9[\"setUTCFullYear\"](\"2003\");if (vEd9.getUTCFullYear().toString(" ascii
    $s2 = "var vSq4 = new Function(\"vQd5\", '{var vEd9 = new Date();vEd9[\"setUTCFullYear\"](\"2003\");if (vEd9.getUTCFullYear().toString(" ascii
    $s3 = "var vFIt5 = new Function(\"vQd5\", '{return vQd5.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vUv2 = vQd5.split(\"###\"); return vUv2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}