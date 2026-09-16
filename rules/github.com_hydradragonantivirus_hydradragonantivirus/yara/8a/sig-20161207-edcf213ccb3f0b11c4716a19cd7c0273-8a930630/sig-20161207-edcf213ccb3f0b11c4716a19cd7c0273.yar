rule sig_20161207_edcf213ccb3f0b11c4716a19cd7c0273 {
  meta:
    description = "datamaliciousorder - file 20161207_edcf213ccb3f0b11c4716a19cd7c0273.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92e44f56da96550cc7c3a91d527b3020e36d1ca5eb5c3d34526f294add6f293b"

  strings:
    $s1 = "var vBLt1 = new Function(\"vIj0\", '{var vEl6 = new Date();vEl6[\"setUTCFullYear\"](\"2003\");if (vEl6.getUTCFullYear().toString" ascii
    $s2 = "var vBLt1 = new Function(\"vIj0\", '{var vEl6 = new Date();vEl6[\"setUTCFullYear\"](\"2003\");if (vEl6.getUTCFullYear().toString" ascii
    $s3 = "var vKEj5 = new Function(\"vIj0\", '{return vIj0.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vHId4 = vIj0.split(\"###\"); return vHId4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}