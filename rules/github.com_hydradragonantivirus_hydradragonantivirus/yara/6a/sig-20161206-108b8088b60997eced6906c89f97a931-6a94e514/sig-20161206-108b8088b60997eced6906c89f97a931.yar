rule sig_20161206_108b8088b60997eced6906c89f97a931 {
  meta:
    description = "datamaliciousorder - file 20161206_108b8088b60997eced6906c89f97a931.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fa463dce9071a75facf49c29f38dc5d173499c0d58df53cdd77f3142ec3bec2"

  strings:
    $s1 = "var vWk6 = new Function(\"s\", '{var vAUs5 = new Date();vAUs5[\"setUTCFullYear\"](\"2003\");if (vAUs5.getUTCFullYear().toString(" ascii
    $s2 = "var vWk6 = new Function(\"s\", '{var vAUs5 = new Date();vAUs5[\"setUTCFullYear\"](\"2003\");if (vAUs5.getUTCFullYear().toString(" ascii
    $s3 = "function vIu6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vFNu2 = s.split(\"##\"); return vFNu2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}