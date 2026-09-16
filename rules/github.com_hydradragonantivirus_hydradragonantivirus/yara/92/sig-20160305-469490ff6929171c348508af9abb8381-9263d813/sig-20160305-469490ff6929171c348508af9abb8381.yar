rule sig_20160305_469490ff6929171c348508af9abb8381 {
  meta:
    description = "datamaliciousorder - file 20160305_469490ff6929171c348508af9abb8381.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63747c30ca99a18cf9c070bebbb0e6507c38b30f09dfc6b766b5ab9b0fed6acd"

  strings:
    $s1  = "var fpyDG = \"ySpHNZ Qub pt.Shell YjjDfIg Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var tw = true  , Gzhf = Mji[7] + \"\" + Mji[9];" fullword ascii
    $s3  = "var Mji = (QPM + \"TTP\" + \" Ukefiql fvaNR XML ream St fUmoGOIo AD WtQGZCl OD\").split(\" \");" fullword ascii
    $s4  = "return nzVcqjt[0] + nzVcqjt[2] + nzVcqjt[4] + \".F\" + nzVcqjt[7] + nzVcqjt[9] + nzVcqjt[12] + nzVcqjt[14];" fullword ascii
    $s5  = "qpGYR.open(svdVX,unSPr,false);" fullword ascii
    $s6  = "var nzVcqjt = \"Sc mIDCtIT r sfbVHUhDT ipting vyQdwra pPP ile QIryIFfstyYStN System OM OojwP Obj CvldIX ect WSayFgS\".split(\" " ascii
    $s7  = "if (((new Date())>0,7521423888)) {" fullword ascii
    $s8  = "function qPoa(drWhC) {" fullword ascii
    $s9  = "return new ActiveXObject(MLyUjH);" fullword ascii
    $s10 = "function JrZxF(MLyUjH) {" fullword ascii
    $s11 = "function AaYO(uIyec,EAbgS) {" fullword ascii
    $s12 = "return LrDs.responseBody;" fullword ascii
    $s13 = "function JiGL(RzCCS) {" fullword ascii
    $s14 = "return Tn.ExpandEnvironmentStrings(fpyDG[6]);" fullword ascii
    $s15 = "function Afeu(qYMQV) {" fullword ascii
    $s16 = "return zmJXO.status;" fullword ascii
    $s17 = "function zvKg(bWeqm) {" fullword ascii
    $s18 = "function bIADzwjGo(KlhCk,fcXyE,Inpqu) {" fullword ascii
    $s19 = "function LsAtLQOA() {" fullword ascii
    $s20 = "if(E>=N.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}