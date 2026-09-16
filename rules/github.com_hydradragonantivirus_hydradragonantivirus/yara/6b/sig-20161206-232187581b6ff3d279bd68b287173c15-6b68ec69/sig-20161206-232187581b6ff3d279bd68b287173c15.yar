rule sig_20161206_232187581b6ff3d279bd68b287173c15 {
  meta:
    description = "datamaliciousorder - file 20161206_232187581b6ff3d279bd68b287173c15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c77de0c339af9bc59e9fd4c7cc9430ebf241188016ef93a1c37f11a05372888"

  strings:
    $s1 = "var vOLv4 = new Function(\"s\", '{var vKc1 = new Date();vKc1[\"setUTCFullYear\"](\"2003\");if (vKc1.getUTCFullYear().toString(10" ascii
    $s2 = "var vOLv4 = new Function(\"s\", '{var vKc1 = new Date();vKc1[\"setUTCFullYear\"](\"2003\");if (vKc1.getUTCFullYear().toString(10" ascii
    $s3 = "function vNi2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vOUg8 = s.split(\"##\"); return vOUg8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}