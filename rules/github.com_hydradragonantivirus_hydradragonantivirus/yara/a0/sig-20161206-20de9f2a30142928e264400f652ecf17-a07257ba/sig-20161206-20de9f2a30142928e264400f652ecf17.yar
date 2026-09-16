rule sig_20161206_20de9f2a30142928e264400f652ecf17 {
  meta:
    description = "datamaliciousorder - file 20161206_20de9f2a30142928e264400f652ecf17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6203cc849ef46d6b7ab29e21be2d11c731cc9ae77d368e2d4a50cddb3e4cbed9"

  strings:
    $s1 = "var vAt2 = new Function(\"s\", '{var vIy7 = new Date();vIy7[\"setUTCFullYear\"](\"2003\");if (vIy7.getUTCFullYear().toString(10)" ascii
    $s2 = "var vAt2 = new Function(\"s\", '{var vIy7 = new Date();vIy7[\"setUTCFullYear\"](\"2003\");if (vIy7.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vUWc7 = s.split(\"##\"); return vUWc7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vMq8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}