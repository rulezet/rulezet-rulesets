rule sig_20161206_aef0b41b2dd7ad50ccebb9f270ccc9bd {
  meta:
    description = "datamaliciousorder - file 20161206_aef0b41b2dd7ad50ccebb9f270ccc9bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5045e9077eaaf89a21080964327bde55013bcd63be1181b4df706639ec0f037b"

  strings:
    $s1 = "var vOXe8 = new Function(\"s\", '{var vPDo0 = new Date();vPDo0[\"setUTCFullYear\"](\"2003\");if (vPDo0.getUTCFullYear().toString" ascii
    $s2 = "var vOXe8 = new Function(\"s\", '{var vPDo0 = new Date();vPDo0[\"setUTCFullYear\"](\"2003\");if (vPDo0.getUTCFullYear().toString" ascii
    $s3 = "function vNQq7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vKFn4 = s.split(\"##\"); return vKFn4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}