rule sig_20160303_d9dc7c3bcb1cd8ce17b5e0c8041a9dc5 {
  meta:
    description = "datamaliciousorder - file 20160303_d9dc7c3bcb1cd8ce17b5e0c8041a9dc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b558eaff3ca5236a233dcd5642a0b625f9a8a6e8441e543de5f993397d0951c2"

  strings:
    $s1  = "var RqmvF = \"RxSTGX ZfD pt.Shell FYarPfN Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var oET = (urU + \"TTP\" + \" yeXBWil Hpnmd XML ream St xdsTbvGe AD sUMebVC OD\").split(\" \");" fullword ascii
    $s3  = "return EzfzKeO[0] + EzfzKeO[2] + EzfzKeO[4] + \".F\" + EzfzKeO[7] + EzfzKeO[9] + EzfzKeO[12] + EzfzKeO[14];" fullword ascii
    $s4  = "var RP = true  , ECjH = oET[7] + \"\" + oET[9];" fullword ascii
    $s5  = "QHaMn.open(cRQiw,BbHMt,false);" fullword ascii
    $s6  = "return GkcS.responseBody;" fullword ascii
    $s7  = "return wzaaV;" fullword ascii
    $s8  = "if (((new Date())>0,7560215888)) {" fullword ascii
    $s9  = "return new ActiveXObject(QDkNLz);" fullword ascii
    $s10 = "function acwiLhk(Gtah) {" fullword ascii
    $s11 = "if (dtYVp > 172605-816){return true;} else {return false;}" fullword ascii
    $s12 = "function GiRGDbvs() {" fullword ascii
    $s13 = "if(r>=s.length) {break;}" fullword ascii
    $s14 = "function SbXPSseXA(eBggQ,VVgbD,qblxI) {" fullword ascii
    $s15 = "function YfTb(PvqEa) {" fullword ascii
    $s16 = "function ROMlIko(GkcS) {" fullword ascii
    $s17 = "function YXUf(QHaMn,BbHMt,cRQiw) {" fullword ascii
    $s18 = "if (hlDTo == 857-657){return true;} else {return false;}" fullword ascii
    $s19 = "function cxZMkNymk(UsaHFaTGTyO) {" fullword ascii
    $s20 = "function ANmB(HgopB) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}