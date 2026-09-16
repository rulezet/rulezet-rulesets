rule sig_20161206_c1010294dd0194759db0cbdbb5a620f9 {
  meta:
    description = "datamaliciousorder - file 20161206_c1010294dd0194759db0cbdbb5a620f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "949401c6fb9e3525b0f6c65b88303c93411d900badb437b84d717e88e00c599f"

  strings:
    $s1 = "var vHu9 = new Function(\"s\", '{var vYAr4 = new Date();vYAr4[\"setUTCFullYear\"](\"2003\");if (vYAr4.getUTCFullYear().toString(" ascii
    $s2 = "var vHu9 = new Function(\"s\", '{var vYAr4 = new Date();vYAr4[\"setUTCFullYear\"](\"2003\");if (vYAr4.getUTCFullYear().toString(" ascii
    $s3 = "function vMQe6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vKk8 = s.split(\"##\"); return vKk8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}