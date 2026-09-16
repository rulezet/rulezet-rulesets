rule sig_20161206_613ab2fa9ef626888c8929dff6e22039 {
  meta:
    description = "datamaliciousorder - file 20161206_613ab2fa9ef626888c8929dff6e22039.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ae6d5faf75f6190fbbac612048d634e4647a2ae7a01a330970867127747746f"

  strings:
    $s1 = "var vSo8 = new Function(\"s\", '{var vYHc6 = new Date();vYHc6[\"setUTCFullYear\"](\"2003\");if (vYHc6.getUTCFullYear().toString(" ascii
    $s2 = "var vSo8 = new Function(\"s\", '{var vYHc6 = new Date();vYHc6[\"setUTCFullYear\"](\"2003\");if (vYHc6.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vBDy2 = s.split(\"##\"); return vBDy2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vXy6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}