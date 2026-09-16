rule sig_20151216_2da077a245a6986b7d3d0c9174110e2a {
  meta:
    description = "datamaliciousorder - file 20151216_2da077a245a6986b7d3d0c9174110e2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b91d5633d42db37f348ea23cd7bb6cccbad86a8720521ac86f70dc10780d697d"

  strings:
    $s1  = "w(Math.cos(234), 2) - 1)));} FvomnYgCL[lMlhAxvKzOP]++;}lMlhAxvKzOP++;} return ArpfTFUfflT}" fullword ascii
    $s2  = "function ihBJosckhotekuvYE(jyGsz){ArpfTFUfflT= '';lMlhAxvKzOP=Math.round((Math.pow(Math.sin(368), 2) + Math.pow(Math.cos(368), 2" ascii
    $s3  = ") - 1));while(true){if (lMlhAxvKzOP >= (254+82)/56){break;}FvomnYgCL[lMlhAxvKzOP]=Math.round((Math.pow(Math.sin(282), 2) + Math." ascii
    $s4  = "pow(Math.cos(282), 2) - 1)); while(true) { if(FvomnYgCL[lMlhAxvKzOP] > jyGsz[lMlhAxvKzOP].length-(-290+397)/107) { break; } if (" ascii
    $s5  = "function ihBJosckhotekuvYE(jyGsz){ArpfTFUfflT= '';lMlhAxvKzOP=Math.round((Math.pow(Math.sin(368), 2) + Math.pow(Math.cos(368), 2" ascii
    $s6  = "function emomSZO(gUoWJPuRDngPZyDEHElpwWhigOROUIUOkIev) {return !CHuduNYrPGp(rUupbyZkqBNgLOw(gUoWJPuRDngPZyDEHElpwWhigOROUIUOkIev" ascii
    $s7  = "function onaziPODmZpSKUMTz(XYNFUpbIBV,TydqAvKWWo) {return parseInt(XYNFUpbIBV,TydqAvKWWo);}" fullword ascii
    $s8  = "var O = new Array();O[0]=[];O[0][0]='d';O[0][1]='a';O[0][2]='d';O[0][3]='a';O[0][4]='46';O[0][5]='3d';O[0][6]='42';O[0][7]='14';" ascii
    $s9  = "function sCNjDcNNKhCrAmUexQvHrYQKFIdmWazRIAfMaqEIHiGdNtBumPMrfm(QWcXRuXwPrHJm,jrCnEhTROlIcvG){ return ivmxYUM[rGKZlvFh[PgRUg(QWc" ascii
    $s10 = "function a(YabaRXXBBHiZ,aUNfycptjIVkIL){YabaRXXBBHiZ.push(aUNfycptjIVkIL);}" fullword ascii
    $s11 = "function sCNjDcNNKhCrAmUexQvHrYQKFIdmWazRIAfMaqEIHiGdNtBumPMrfm(QWcXRuXwPrHJm,jrCnEhTROlIcvG){ return ivmxYUM[rGKZlvFh[PgRUg(QWc" ascii
    $s12 = "function k(LBqlsPKYqqBrbj,eCpoqIznrMQzt,QknbdTFaqlU) {LBqlsPKYqqBrbj[eCpoqIznrMQzt]=QknbdTFaqlU;}" fullword ascii
    $s13 = ",'i','z','-','V','W',')','o','C','1','{','S','#','X','Z','*','Y',':','%','4','9','M','_','Z','I','#','R','r','(','[',' ',String." ascii
    $s14 = "q);return GMAqB;}" fullword ascii
    $s15 = "function PgRUg(PvvmsBgnNrp,adGBKdRAGhIoH,bvdYPKzq){XLoE=onaziPODmZpSKUMTz(PvvmsBgnNrp,adGBKdRAGhIoH);GMAqB=XLoE.toString(bvdYPKz" ascii
    $s16 = "function emomSZO(gUoWJPuRDngPZyDEHElpwWhigOROUIUOkIev) {return !CHuduNYrPGp(rUupbyZkqBNgLOw(gUoWJPuRDngPZyDEHElpwWhigOROUIUOkIev" ascii
    $s17 = "function rUupbyZkqBNgLOw(DaAboTKJfvVCgXvIlzP) {return parseFloat(DaAboTKJfvVCgXvIlzP);}" fullword ascii
    $s18 = "var O = new Array();O[0]=[];O[0][0]='d';O[0][1]='a';O[0][2]='d';O[0][3]='a';O[0][4]='46';O[0][5]='3d';O[0][6]='42';O[0][7]='14';" ascii
    $s19 = "function WqlmanKIOAvf(mYxyKRwjhPOho) {return isFinite(mYxyKRwjhPOho);}" fullword ascii
    $s20 = "function PgRUg(PvvmsBgnNrp,adGBKdRAGhIoH,bvdYPKzq){XLoE=onaziPODmZpSKUMTz(PvvmsBgnNrp,adGBKdRAGhIoH);GMAqB=XLoE.toString(bvdYPKz" ascii

  condition:
    uint16(0) == 0x4772 and
    8 of them
}