rule sig_20160314_3a16aa4ae6b08023f982fd66378ee2ae {
  meta:
    description = "datamaliciousorder - file 20160314_3a16aa4ae6b08023f982fd66378ee2ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d680dbb0168efff53b9b30a9f862e455a42da90f87488c651742c3b3b29da014"

  strings:
    $s1  = "var IlqML = \"kGnzqe:XAT:pt.Shell:KDPGsOf:Scri:Glum:%TE:MP%:\\\\:goMrdezjV:jNtSRO:eSPQNDS:RePxp\".split(\":\");" fullword ascii
    $s2  = "return XKnXahm[0] + XKnXahm[2] + XKnXahm[4] + \".F\" + XKnXahm[7] + XKnXahm[9] + XKnXahm[12] + XKnXahm[14];" fullword ascii
    $s3  = "var yC = true  , GLmv = rwk[7] + rwk[9] + rwk[11];" fullword ascii
    $s4  = "var XKnXahm = \"Sc OpTGOUW r PeubVgDvS ipting GzqcoBe Oit ile hFmufZcizCFioZ System bX ezxzS Obj biXURp ect RxxWxuq ncdGq\".spli" ascii
    $s5  = "var XKnXahm = \"Sc OpTGOUW r PeubVgDvS ipting GzqcoBe Oit ile hFmufZcizCFioZ System bX ezxzS Obj biXURp ect RxxWxuq ncdGq\".spli" ascii
    $s6  = "var rwk = (\"2.XMLHTTP KEccCoB jaRZF XML ream St gTYGFWtC AD RfBddnH O NaJZ D\").split(\" \");" fullword ascii
    $s7  = "ochwh.open(gvOjl,ktEMo,false);" fullword ascii
    $s8  = "function UGUO(ochwh,ktEMo,gvOjl) {" fullword ascii
    $s9  = "return USWnBD.position=670-670;" fullword ascii
    $s10 = "return XbMoDEz(Zy,IlqML[256-250]+IlqML[963-956]+IlqML[942-934]);" fullword ascii
    $s11 = "return ULV.size;" fullword ascii
    $s12 = "function DHgi(smSBl) {" fullword ascii
    $s13 = "function moxFZmOiM() {" fullword ascii
    $s14 = "return rjNesdm" fullword ascii
    $s15 = "function VdWDN(USWnBD) {" fullword ascii
    $s16 = "function cZtG(hiHdw) {" fullword ascii
    $s17 = "return HUzH.ExpandEnvironmentStrings(nmeLf);" fullword ascii
    $s18 = "return OToR.responseBody;" fullword ascii
    $s19 = "if (Y >= OkQCq.length) {break;}" fullword ascii
    $s20 = "TRq = Z; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}