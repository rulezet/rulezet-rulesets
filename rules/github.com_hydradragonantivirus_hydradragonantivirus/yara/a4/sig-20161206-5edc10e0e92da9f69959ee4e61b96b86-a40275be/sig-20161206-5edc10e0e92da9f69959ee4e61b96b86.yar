rule sig_20161206_5edc10e0e92da9f69959ee4e61b96b86 {
  meta:
    description = "datamaliciousorder - file 20161206_5edc10e0e92da9f69959ee4e61b96b86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "361bb8c4d661b451404ba1c753bcc06eb251907d1a69b48b2d3e40e8c36c5bbf"

  strings:
    $s1 = "var vVn4 = new Function(\"s\", '{var vJq2 = new Date();vJq2[\"setUTCFullYear\"](\"2003\");if (vJq2.getUTCFullYear().toString(10)" ascii
    $s2 = "var vVn4 = new Function(\"s\", '{var vJq2 = new Date();vJq2[\"setUTCFullYear\"](\"2003\");if (vJq2.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vFj0 = s.split(\"##\"); return vFj0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vASg1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}