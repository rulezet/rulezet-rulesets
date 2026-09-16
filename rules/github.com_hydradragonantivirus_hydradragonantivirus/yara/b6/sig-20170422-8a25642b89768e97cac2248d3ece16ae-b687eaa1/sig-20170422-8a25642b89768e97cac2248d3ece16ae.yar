rule sig_20170422_8a25642b89768e97cac2248d3ece16ae {
  meta:
    description = "datamaliciousorder - file 20170422_8a25642b89768e97cac2248d3ece16ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fa8ad1f0fbaa42252de1970e49c8dda40387ff0a3c42f1f61c8b383f49c0316"

  strings:
    $s1 = "if (tXfdQkgcMhyYBwbi.FolderExists(\"c\"+\":\\\\w\"+\"iNdo\"+\"Ws\") == true) {" fullword ascii
    $s2 = "return cmyxpOYrRUHbEFVzX.split(VRMwlGPhztJDuaxTSY).join(vPXmydjYJprWesLuq); }" fullword ascii
    $s3 = "\"plat?s:22:29:2B:22:\"+" fullword ascii
    $s4 = "function GomwsANYScdDfOjRV(cmyxpOYrRUHbEFVzX, VRMwlGPhztJDuaxTSY, vPXmydjYJprWesLuq) { " fullword ascii
    $s5 = "\"?val(un?scap?(\\\"var:20wsh:20:3D:2\"+" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}