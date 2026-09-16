rule sig_20161206_a46cb62765be2c78b2dc390ee5074e15 {
  meta:
    description = "datamaliciousorder - file 20161206_a46cb62765be2c78b2dc390ee5074e15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed8b09a6eb43f0fed4e674958f454dd1dbcc439d492a27409346de50fec7072e"

  strings:
    $s1 = "var vRJi2 = new Function(\"s\", '{var vJGo2 = new Date();vJGo2[\"setUTCFullYear\"](\"2003\");if (vJGo2.getUTCFullYear().toString" ascii
    $s2 = "var vRJi2 = new Function(\"s\", '{var vJGo2 = new Date();vJGo2[\"setUTCFullYear\"](\"2003\");if (vJGo2.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vACd3 = s.split(\"##\"); return vACd3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vFUd5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}