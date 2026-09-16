rule sig_20161206_c581d36b739a5bbc7b48fcb9035dc04e {
  meta:
    description = "datamaliciousorder - file 20161206_c581d36b739a5bbc7b48fcb9035dc04e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac7065326a0fcffe92c049a0c8b8284d64f1a203fbb1858a74b46c8bfa78ed3f"

  strings:
    $s1 = "var vCb5 = new Function(\"s\", '{var vNIp1 = new Date();vNIp1[\"setUTCFullYear\"](\"2003\");if (vNIp1.getUTCFullYear().toString(" ascii
    $s2 = "var vCb5 = new Function(\"s\", '{var vNIp1 = new Date();vNIp1[\"setUTCFullYear\"](\"2003\");if (vNIp1.getUTCFullYear().toString(" ascii
    $s3 = "function vRTr4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vRIt7 = s.split(\"##\"); return vRIt7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}