rule sig_20161206_e3eb3a4ed4f9bbb7570b2ba0b7856f0f {
  meta:
    description = "datamaliciousorder - file 20161206_e3eb3a4ed4f9bbb7570b2ba0b7856f0f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "400e9a844ee2abaf1cbdb37b81eb78b601d470e2afd04c9c60b80c7da2eb0ae0"

  strings:
    $s1 = "var vMOl1 = new Function(\"s\", '{var vZu4 = new Date();vZu4[\"setUTCFullYear\"](\"2003\");if (vZu4.getUTCFullYear().toString(10" ascii
    $s2 = "var vMOl1 = new Function(\"s\", '{var vZu4 = new Date();vZu4[\"setUTCFullYear\"](\"2003\");if (vZu4.getUTCFullYear().toString(10" ascii
    $s3 = "function vGKb1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vOQf9 = s.split(\"##\"); return vOQf9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}