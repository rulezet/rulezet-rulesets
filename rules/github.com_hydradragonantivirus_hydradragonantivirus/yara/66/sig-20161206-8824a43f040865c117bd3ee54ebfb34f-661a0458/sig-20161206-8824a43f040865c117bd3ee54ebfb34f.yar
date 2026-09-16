rule sig_20161206_8824a43f040865c117bd3ee54ebfb34f {
  meta:
    description = "datamaliciousorder - file 20161206_8824a43f040865c117bd3ee54ebfb34f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca5fcd39d59926cdaf1578aa719d2462cbbd02c9904bac1a4c936e0240efd7d7"

  strings:
    $s1 = "var vTv2 = new Function(\"s\", '{var vZn1 = new Date();vZn1[\"setUTCFullYear\"](\"2003\");if (vZn1.getUTCFullYear().toString(10)" ascii
    $s2 = "var vTv2 = new Function(\"s\", '{var vZn1 = new Date();vZn1[\"setUTCFullYear\"](\"2003\");if (vZn1.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vIUw6 = s.split(\"##\"); return vIUw6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vCp3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}