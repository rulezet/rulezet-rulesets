rule sig_20161206_57180c90f461f0ee5c809e8a22eb4b75 {
  meta:
    description = "datamaliciousorder - file 20161206_57180c90f461f0ee5c809e8a22eb4b75.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f33efae3604d9a3fbf924ee9ab354934db161b10cbcb34bbb99b913b9204df0"

  strings:
    $s1 = "var vKTc6 = new Function(\"s\", '{var vEVm6 = new Date();vEVm6[\"setUTCFullYear\"](\"2003\");if (vEVm6.getUTCFullYear().toString" ascii
    $s2 = "var vKTc6 = new Function(\"s\", '{var vEVm6 = new Date();vEVm6[\"setUTCFullYear\"](\"2003\");if (vEVm6.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vFf7 = s.split(\"##\"); return vFf7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vIc0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}