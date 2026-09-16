rule sig_20161206_bcc4c4311c29da04dceefda8a3b18d9c {
  meta:
    description = "datamaliciousorder - file 20161206_bcc4c4311c29da04dceefda8a3b18d9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27a2be8ab1301a7564d9fa827a43c9658b88b31e54a50ab290c2ba888f37cf46"

  strings:
    $s1 = "var vFVx4 = new Function(\"s\", '{var vVDf0 = new Date();vVDf0[\"setUTCFullYear\"](\"2003\");if (vVDf0.getUTCFullYear().toString" ascii
    $s2 = "var vFVx4 = new Function(\"s\", '{var vVDf0 = new Date();vVDf0[\"setUTCFullYear\"](\"2003\");if (vVDf0.getUTCFullYear().toString" ascii
    $s3 = "function vGTa2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vMLd4 = s.split(\"##\"); return vMLd4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}