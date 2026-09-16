rule sig_20161206_5c18bf6f348ec3fe849c07da62500004 {
  meta:
    description = "datamaliciousorder - file 20161206_5c18bf6f348ec3fe849c07da62500004.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fe707aac8b22a2139030b68ca4306dc3d5e93bfad0281918eb75981ee2e8337"

  strings:
    $s1 = "var vIn2 = new Function(\"s\", '{var vVBk6 = new Date();vVBk6[\"setUTCFullYear\"](\"2003\");if (vVBk6.getUTCFullYear().toString(" ascii
    $s2 = "var vIn2 = new Function(\"s\", '{var vVBk6 = new Date();vVBk6[\"setUTCFullYear\"](\"2003\");if (vVBk6.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vDOi3 = s.split(\"##\"); return vDOi3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vVZz7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}