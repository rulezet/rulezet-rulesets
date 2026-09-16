rule sig_20160313_6be68def4f7500989a5b145891007d16 {
  meta:
    description = "datamaliciousorder - file 20160313_6be68def4f7500989a5b145891007d16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5549b426b4f37b5d8f45ce02a2d1ffd0c16cdf0ffd648745c08a23801d002b5b"

  strings:
    $s1  = "var ay = true  , WNXM = Lcv[7] + Lcv[9] + Lcv[11];" fullword ascii
    $s2  = "return HJQKTLg[0] + HJQKTLg[2] + HJQKTLg[4] + \".F\" + HJQKTLg[7] + HJQKTLg[9] + HJQKTLg[12] + HJQKTLg[14];" fullword ascii
    $s3  = "var Lcv = (\"2.XMLHTTP IWHATsl nrHhD XML ream St jrymRuWp AD XeWMCXt O DQgc D\").split(\" \");" fullword ascii
    $s4  = "var HJQKTLg = \"Sc JhEJMlY r ofXnNtwyC ipting HfOkvvA hFw ile CdCztBpTpNnEfn System xk SsrRO Obj NMrgTB ect IcMEvia\".split(\" " ascii
    $s5  = "IYRQL.open(UHNhx,fmyWv,false);" fullword ascii
    $s6  = "return UGMyn;" fullword ascii
    $s7  = "if (T >= ZcwHv.length) {break;}" fullword ascii
    $s8  = "function HzPR(RbJaT) {" fullword ascii
    $s9  = "function HHswwVInw() {" fullword ascii
    $s10 = "if(C>=Z.length) {break;}" fullword ascii
    $s11 = "function RXzlFdiWM(OrWYZiySHJu) {" fullword ascii
    $s12 = "if (zUeJI == 724-524){return true;} else {return false;}" fullword ascii
    $s13 = "return jmI.size;" fullword ascii
    $s14 = "function eneTy(qIJONx) {" fullword ascii
    $s15 = "function DRWqxTN(pyVg,mXkoa) {" fullword ascii
    $s16 = "function NqzK(NhcJF,bRSSi) {" fullword ascii
    $s17 = "function pAby(zUeJI) {" fullword ascii
    $s18 = "if (NAxZP > 192176-581){return true;} else {return false;}" fullword ascii
    $s19 = "function AiVg(HLfUA) {" fullword ascii
    $s20 = "function gGma(srgAH) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}