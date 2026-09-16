rule sig_20161207_513e80fde7986f682153590c8f457f7e {
  meta:
    description = "datamaliciousorder - file 20161207_513e80fde7986f682153590c8f457f7e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c01a42356bf6b5d5e61374679e00eb3b38f42458f75c53c3758010941d6cd806"

  strings:
    $s1 = "var vNh4 = new Function(\"vDm3\", '{var vSu8 = new Date();vSu8[\"setUTCFullYear\"](\"2003\");if (vSu8.getUTCFullYear().toString(" ascii
    $s2 = "var vNh4 = new Function(\"vDm3\", '{var vSu8 = new Date();vSu8[\"setUTCFullYear\"](\"2003\");if (vSu8.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vUl7 = vDm3.split(\"###\"); return vUl7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vFc6 = new Function(\"vDm3\", '{return vDm3.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}