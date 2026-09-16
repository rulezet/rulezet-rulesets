rule sig_20161206_baa4fef9ef7eb8925529ce8238869f66 {
  meta:
    description = "datamaliciousorder - file 20161206_baa4fef9ef7eb8925529ce8238869f66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e28ffcfb62a5ea29f8a3d502dcfae0e2f08e1ecfc22a3933565faf20980065f2"

  strings:
    $s1 = "var vIPk0 = new Function(\"s\", '{var vVCm1 = new Date();vVCm1[\"setUTCFullYear\"](\"2003\");if (vVCm1.getUTCFullYear().toString" ascii
    $s2 = "var vIPk0 = new Function(\"s\", '{var vVCm1 = new Date();vVCm1[\"setUTCFullYear\"](\"2003\");if (vVCm1.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vDSd4 = s.split(\"##\"); return vDSd4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vUKh4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}