rule sig_20151216_2cdea354cc59fefadfa34d17177f6cd2 {
  meta:
    description = "datamaliciousorder - file 20151216_2cdea354cc59fefadfa34d17177f6cd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0406f1c3b4e1f4572a0dd6c2f2cbe6f5c5fb91278aff302b06100ca4eb3444a"

  strings:
    $s1  = ") - 1));while(true){if (ydNnnoylhsm >= (1409+7)/236){break;}dBkwAhNWp[ydNnnoylhsm]=Math.round((Math.pow(Math.sin(578), 2) + Math" ascii
    $s2  = "ow(Math.cos(332), 2) - 1)));} dBkwAhNWp[ydNnnoylhsm]++;}ydNnnoylhsm++;} return zXyeiQBbCME}" fullword ascii
    $s3  = ".pow(Math.cos(578), 2) - 1)); while(true) { if(dBkwAhNWp[ydNnnoylhsm] > VdVAq[ydNnnoylhsm].length-(-368+941)/573) { break; } if " ascii
    $s4  = "function IYgiIflgpZmsgyVfI(VdVAq){zXyeiQBbCME= '';ydNnnoylhsm=Math.round((Math.pow(Math.sin(276), 2) + Math.pow(Math.cos(276), 2" ascii
    $s5  = "function IYgiIflgpZmsgyVfI(VdVAq){zXyeiQBbCME= '';ydNnnoylhsm=Math.round((Math.pow(Math.sin(276), 2) + Math.pow(Math.cos(276), 2" ascii
    $s6  = "function nsNys(GoMKeAIgbfB,tqrGWJNTBOnrR,UyxNPLmR){MgnD=LfLuPKnGqlmLqLosM(GoMKeAIgbfB,tqrGWJNTBOnrR);nUwwN=MgnD.toString(UyxNPLm" ascii
    $s7  = "var a = new Array();a[0]=[];a[0][0]='d';a[0][1]='a';a[0][2]='d';a[0][3]='a';a[0][4]='46';a[0][5]='3d';a[0][6]='42';a[0][7]='14';" ascii
    $s8  = "function rMdTIRSriHVSPKEUAKwJiKmQloEPsaFalqEAKHukUisGZLXkkzZJQT(DWsUYIOGGRATh,uZpkownKvechaC){ return QAyGkPT[GlMslzpm[nsNys(DWs" ascii
    $s9  = "var a = new Array();a[0]=[];a[0][0]='d';a[0][1]='a';a[0][2]='d';a[0][3]='a';a[0][4]='46';a[0][5]='3d';a[0][6]='42';a[0][7]='14';" ascii
    $s10 = "function d(rWxsdFTVzjUosK,GldKzMQhKjMij,fjITBmzKUIW) {rWxsdFTVzjUosK[GldKzMQhKjMij]=fjITBmzKUIW;}" fullword ascii
    $s11 = "function AscVgDLpJsP(BFNxtShsizLSgg) {return isNaN(BFNxtShsizLSgg);}" fullword ascii
    $s12 = "function LfLuPKnGqlmLqLosM(zgyklNZoFR,fCHiZYMsFo) {return parseInt(zgyklNZoFR,fCHiZYMsFo);}" fullword ascii
    $s13 = "R);return nUwwN;}" fullword ascii
    $s14 = "function rMdTIRSriHVSPKEUAKwJiKmQloEPsaFalqEAKHukUisGZLXkkzZJQT(DWsUYIOGGRATh,uZpkownKvechaC){ return QAyGkPT[GlMslzpm[nsNys(DWs" ascii
    $s15 = "function nsNys(GoMKeAIgbfB,tqrGWJNTBOnrR,UyxNPLmR){MgnD=LfLuPKnGqlmLqLosM(GoMKeAIgbfB,tqrGWJNTBOnrR);nUwwN=MgnD.toString(UyxNPLm" ascii
    $s16 = "function SEomFYGajTmIlwI(nQuDkPsKfkeVpVmbPBG) {return parseFloat(nQuDkPsKfkeVpVmbPBG);}" fullword ascii
    $s17 = "function N(ujDLZiaolvPD,mVQoLvGOELApvM){ujDLZiaolvPD.push(mVQoLvGOELApvM);}" fullword ascii
    $s18 = "function QZBgDpcUXByF(ThmnloQGerKnJ) {return isFinite(ThmnloQGerKnJ);}" fullword ascii
    $s19 = "function euMgDRm(UjHaeTCEtkJNhsWwsXxlSpTpicrlRbPzqIyx) {return !AscVgDLpJsP(SEomFYGajTmIlwI(UjHaeTCEtkJNhsWwsXxlSpTpicrlRbPzqIyx" ascii
    $s20 = "function IOHTXTQDLglRPhm(RONfSBtvoNulImDBJ,ZAlOjQMsKRHtYXuWtjcENuoqQDTCUboWVi,wpDsTWQXdfonuOjMGZyPljvKNPATtSncAVt){eval(RONfSBtv" ascii

  condition:
    uint16(0) == 0x6c47 and
    8 of them
}