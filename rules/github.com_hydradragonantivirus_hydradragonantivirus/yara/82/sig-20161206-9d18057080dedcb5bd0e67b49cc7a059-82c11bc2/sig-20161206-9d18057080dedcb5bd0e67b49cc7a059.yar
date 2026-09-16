rule sig_20161206_9d18057080dedcb5bd0e67b49cc7a059 {
  meta:
    description = "datamaliciousorder - file 20161206_9d18057080dedcb5bd0e67b49cc7a059.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5516fddf0d72a092f6d996bddb5196dfc9df3e090cd795aa3c201070a795491f"

  strings:
    $s1 = "var vKQg2 = new Function(\"s\", '{var vHx2 = new Date();vHx2[\"setUTCFullYear\"](\"2003\");if (vHx2.getUTCFullYear().toString(10" ascii
    $s2 = "var vKQg2 = new Function(\"s\", '{var vHx2 = new Date();vHx2[\"setUTCFullYear\"](\"2003\");if (vHx2.getUTCFullYear().toString(10" ascii
    $s3 = "function vPEy8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vLRo2 = s.split(\"##\"); return vLRo2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}