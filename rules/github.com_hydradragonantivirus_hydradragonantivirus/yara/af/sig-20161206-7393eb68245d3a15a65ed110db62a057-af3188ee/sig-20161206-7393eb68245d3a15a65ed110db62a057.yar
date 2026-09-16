rule sig_20161206_7393eb68245d3a15a65ed110db62a057 {
  meta:
    description = "datamaliciousorder - file 20161206_7393eb68245d3a15a65ed110db62a057.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d562931d3b909962584d8b4622e4551a922b1739e25c1f006520fa5cd5e94abf"

  strings:
    $s1 = "var vZMc3 = new Function(\"s\", '{var vYZw1 = new Date();vYZw1[\"setUTCFullYear\"](\"2003\");if (vYZw1.getUTCFullYear().toString" ascii
    $s2 = "var vZMc3 = new Function(\"s\", '{var vYZw1 = new Date();vYZw1[\"setUTCFullYear\"](\"2003\");if (vYZw1.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vVMb8 = s.split(\"##\"); return vVMb8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vMs3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}