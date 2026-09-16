rule sig_20160307_f122aa362a83483f533f0ce2ea10064d {
  meta:
    description = "datamaliciousorder - file 20160307_f122aa362a83483f533f0ce2ea10064d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e69d0bffad9b9a7938018250fa166fda726702cddcc0d96a6e88cb0d8ce0d2d"

  strings:
    $s1  = "var dZyCDMg = \"Sc IYsfSiC r KnwdgtGHH ipting LLjKcVw Fms ile UqpXFXTrxqJsAx System kw zgeXq Obj uTcomV ect bBnELsH\".split(\" " ascii
    $s2  = "return dZyCDMg[0] + dZyCDMg[2] + dZyCDMg[4] + \".F\" + dZyCDMg[7] + dZyCDMg[9] + dZyCDMg[12] + dZyCDMg[14];" fullword ascii
    $s3  = "var fQ = true  , YBPG = OPL[7] + OPL[9] + OPL[11];" fullword ascii
    $s4  = "RFwyq.open(GbPwM,XHcny,false);" fullword ascii
    $s5  = "return new ActiveXObject(sSLYgb);" fullword ascii
    $s6  = "return iHRRj.replace(new RegExp('!','g'), 'e');" fullword ascii
    $s7  = "function NEwgs(sSLYgb) {" fullword ascii
    $s8  = "function Qiuo(znqLm) {" fullword ascii
    $s9  = "function daVw(AQzMs) {" fullword ascii
    $s10 = "function ldCVahkSv(NFiAU,rPHoJ,wWRDJ,duke) {" fullword ascii
    $s11 = "function FDBx(XraBQ) {" fullword ascii
    $s12 = "function ngfr(aUXXj) {" fullword ascii
    $s13 = "function BNPk(RFwyq,XHcny,GbPwM) {" fullword ascii
    $s14 = "function xekZ(ubDnh) {" fullword ascii
    $s15 = "function bRbi(yhUze) {" fullword ascii
    $s16 = "return TMMOWoy" fullword ascii
    $s17 = "if (((new Date())>0,7414432888)) {" fullword ascii
    $s18 = "function dwOFoRGMj(BIzGQIOZYcq) {" fullword ascii
    $s19 = "function DREz(wxDYk,SxKnX) {" fullword ascii
    $s20 = "function zgoByNw(ZBHr) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}