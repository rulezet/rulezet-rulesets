rule sig_20170421_f23d90e6e6dd6cae96f15206722d9c81 {
  meta:
    description = "datamaliciousorder - file 20170421_f23d90e6e6dd6cae96f15206722d9c81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bfae0ef472ec32fb95b7794ecd2295ef9be2a17ed07f7fccdc31851a54a709d"

  strings:
    $s1 = "function skGiJKAxSoCzQME(VBDoljGkRgxpNOd) { return String.fromCharCode(VBDoljGkRgxpNOd); }" fullword ascii
    $s2 = "if (ksyUjSILaEMPAzxNTl.FolderExists(\"c\"+\":\\\\W\"+\"iNdO\"+\"Ws\") == true) {" fullword ascii
    $s3 = "function rujqclJUiwPQDoEBFSL(tdelDSburhRsWLzjfcE, HmolJckpFPjXxTUCARq) { " fullword ascii
    $s4 = "return tdelDSburhRsWLzjfcE.split(HmolJckpFPjXxTUCARq).join(\"\"); }" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}