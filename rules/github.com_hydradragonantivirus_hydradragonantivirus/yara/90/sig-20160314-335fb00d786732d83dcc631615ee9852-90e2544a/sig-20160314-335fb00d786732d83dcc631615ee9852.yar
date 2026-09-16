rule sig_20160314_335fb00d786732d83dcc631615ee9852 {
  meta:
    description = "datamaliciousorder - file 20160314_335fb00d786732d83dcc631615ee9852.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee390912d833caa36a57279061fb2d404048794830a3de7a0d7473dee2da3f73"

  strings:
    $s1  = "var vt = true  , vcEK = bOD[7] + bOD[9] + bOD[11];" fullword ascii
    $s2  = "return MjuwUCG[0] + MjuwUCG[2] + MjuwUCG[4] + \".F\" + MjuwUCG[7] + MjuwUCG[9] + MjuwUCG[12] + MjuwUCG[14];" fullword ascii
    $s3  = "var bOD = (\"2.XMLHTTP jIYzbzs ZdiJL XML ream St oFlDGMdQ AD zXilWOd O MpPK D\").split(\" \");" fullword ascii
    $s4  = "JIAOS.open(DbFcF,FOgGM,false);" fullword ascii
    $s5  = "return aiFH.ExpandEnvironmentStrings(sMTwK);" fullword ascii
    $s6  = "function CmOU(ajaVf) {" fullword ascii
    $s7  = "hzI = N; break; " fullword ascii
    $s8  = "if (ijhxw > 182996-928){return true;} else {return false;}" fullword ascii
    $s9  = "function TPqw(ejTkD) {" fullword ascii
    $s10 = "function wIDMLjBpe(qWjvviHCXhj) {" fullword ascii
    $s11 = "function Ytvh(gfBiZ) {" fullword ascii
    $s12 = "function jDVn(dKjfy,gXzTP) {" fullword ascii
    $s13 = "return pjFn.responseBody;" fullword ascii
    $s14 = "function xZOEeaVb(TZF) {" fullword ascii
    $s15 = "return TZF.size;" fullword ascii
    $s16 = "return aDpus;" fullword ascii
    $s17 = "return OfyRgst(sy,TLjzh[627-621]+TLjzh[996-989]+TLjzh[297-289]);" fullword ascii
    $s18 = "return XEEPBI.position=542-542;" fullword ascii
    $s19 = "if (Y >= ejTkD.length) {break;}" fullword ascii
    $s20 = "if (atdvl == 405-205){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}