rule sig_20160428_7434bc9670d7de2312d749cd66fb85f5 {
  meta:
    description = "datamaliciousorder - file 20160428_7434bc9670d7de2312d749cd66fb85f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c97b308e25192da2c7b3b9588e6f147093850c24b800feaf583e47e0d73c9b6"

  strings:
    $s1  = "while (PFIC < DtpklyuH - (3424, 9711, 2682, 3645, 5445, 6059, 4595, 2164, 2)) {" fullword ascii
    $s2  = "function kYGdhPf(jPx, XbxDlL) {" fullword ascii
    $s3  = "return Tydut + Gbo + wescEW + rut + VNInp + Mnl;" fullword ascii
    $s4  = "var HcBU = KLiP(\"022053035097017008055107110022107\") + XVYjFspK;" fullword ascii
    $s5  = "var XVYjFspK = Lbik[KLiP(\"050061051028004021049034032025013000013046060032\")]((3035, 2845, 684, 2)) + '\\\\' + Lbik[KLiP(\"050" ascii
    $s6  = "var XVYjFspK = Lbik[KLiP(\"050061051028004021049034032025013000013046060032\")]((3035, 2845, 684, 2)) + '\\\\' + Lbik[KLiP(\"050" ascii
    $s7  = "if (5 === true) {" fullword ascii
    $s8  = "if (1 == true) {" fullword ascii
    $s9  = "return xIWK;" fullword ascii
    $s10 = "mGuYu[KLiP(\"038057049042032031020034045016\")](XVYjFspK);" fullword ascii
    $s11 = "return leMnls;" fullword ascii
    $s12 = "function KLiP(zJbDre) {" fullword ascii
    $s13 = "var OiLre = qTvk[KLiP(\"038059053038004004020062045025005014012047\")];" fullword ascii
    $s14 = "switch (\"yxLgHnRY\") {" fullword ascii
    $s15 = "function jMyMy() {" fullword ascii
    $s16 = "function SrOj() {" fullword ascii
    $s17 = "switch (737) {" fullword ascii
    $s18 = "function TWdaSh() {" fullword ascii
    $s19 = "var gHWM = KdBy[KLiP(\"025061041040000024\")];" fullword ascii
    $s20 = "return tkDs;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}