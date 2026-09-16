rule sig_20161206_a93839b21e4205dc338ebb9f43ee8f9c {
  meta:
    description = "datamaliciousorder - file 20161206_a93839b21e4205dc338ebb9f43ee8f9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c0798372925673831a820126c5c5ef39c01390ebcd624b9133aff90ebba7c96"

  strings:
    $s1 = "var vEWp9 = new Function(\"s\", '{var vGn8 = new Date();vGn8[\"setUTCFullYear\"](\"2003\");if (vGn8.getUTCFullYear().toString(10" ascii
    $s2 = "var vEWp9 = new Function(\"s\", '{var vGn8 = new Date();vGn8[\"setUTCFullYear\"](\"2003\");if (vGn8.getUTCFullYear().toString(10" ascii
    $s3 = "function vPZm6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vJHx9 = s.split(\"##\"); return vJHx9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}