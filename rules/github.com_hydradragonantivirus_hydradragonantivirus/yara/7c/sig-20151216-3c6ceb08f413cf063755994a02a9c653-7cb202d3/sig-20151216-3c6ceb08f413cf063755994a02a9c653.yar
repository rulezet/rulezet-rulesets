rule sig_20151216_3c6ceb08f413cf063755994a02a9c653 {
  meta:
    description = "datamaliciousorder - file 20151216_3c6ceb08f413cf063755994a02a9c653.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df0d74edc43851cc220ebda4308a904d1327fdd03ce42c5f7d59efc4ed676f5b"

  strings:
    $s1  = "ow(Math.cos(27), 2) - 1)); while(true) { if(zMPcomoZh[EJBBHOGSYAl] > zHdvD[EJBBHOGSYAl].length-(-7+78)/71) { break; } if (xSeCzE" ascii
    $s2  = ".cos(745), 2) - 1)));} zMPcomoZh[EJBBHOGSYAl]++;}EJBBHOGSYAl++;} return YIFTUSQuIjR}" fullword ascii
    $s3  = "- 1));while(true){if (EJBBHOGSYAl >= (-26+782)/126){break;}zMPcomoZh[EJBBHOGSYAl]=Math.round((Math.pow(Math.sin(27), 2) + Math.p" ascii
    $s4  = "function LqoctcuTWHvncFFNy(zHdvD){YIFTUSQuIjR= '';EJBBHOGSYAl=Math.round((Math.pow(Math.sin(53), 2) + Math.pow(Math.cos(53), 2) " ascii
    $s5  = "zRCZUTUmSHoKotEaaZTExEOJcYz([zHdvD[EJBBHOGSYAl][zMPcomoZh[EJBBHOGSYAl]]], Math.round((Math.pow(Math.sin(745), 2) + Math.pow(Math" ascii
    $s6  = "function LqoctcuTWHvncFFNy(zHdvD){YIFTUSQuIjR= '';EJBBHOGSYAl=Math.round((Math.pow(Math.sin(53), 2) + Math.pow(Math.cos(53), 2) " ascii
    $s7  = "var T = new Array();T[0]=[];T[0][0]='d';T[0][1]='a';T[0][2]='d';T[0][3]='a';T[0][4]='46';T[0][5]='3d';T[0][6]='42';T[0][7]='14';" ascii
    $s8  = "function UhzmeLDiDKBcrTl(IRnLrhcryaufCdpfAeh) {return parseFloat(IRnLrhcryaufCdpfAeh);}" fullword ascii
    $s9  = "function W(WLYEffpoUaoL,CwSrKPTPOOjJid){WLYEffpoUaoL.push(CwSrKPTPOOjJid);}" fullword ascii
    $s10 = ",'d','C','(','o','7','W','5','e','@','p','X','X','p','H','Y','8','y','J','%',')',')','Z','f','B','0','q','[','g','3','a',String." ascii
    $s11 = "function dRyCH(wNVyfOMIUnJ,PrKaWFaLUOCHi,urbScqpY){BcIF=lpGuEFrcGYXwhPWma(wNVyfOMIUnJ,PrKaWFaLUOCHi);PVQfH=BcIF.toString(urbScqp" ascii
    $s12 = "function xSeCzEc(cPsUGhiVwoXnykAWuKHAwKTcqGClfrXlZIhw) {return !tEXjnBsaVOF(UhzmeLDiDKBcrTl(cPsUGhiVwoXnykAWuKHAwKTcqGClfrXlZIhw" ascii
    $s13 = "function lpGuEFrcGYXwhPWma(tJXZlXgJqz,OSQlmdFzIi) {return parseInt(tJXZlXgJqz,OSQlmdFzIi);}" fullword ascii
    $s14 = "function tEXjnBsaVOF(SycNtvHiVASyRG) {return isNaN(SycNtvHiVASyRG);}" fullword ascii
    $s15 = "function u(IFrZdUCDCckIbS,uOYFmWQByUMTC,QmCExWsJfOB) {IFrZdUCDCckIbS[uOYFmWQByUMTC]=QmCExWsJfOB;}" fullword ascii
    $s16 = "var T = new Array();T[0]=[];T[0][0]='d';T[0][1]='a';T[0][2]='d';T[0][3]='a';T[0][4]='46';T[0][5]='3d';T[0][6]='42';T[0][7]='14';" ascii
    $s17 = "Y);return PVQfH;}" fullword ascii
    $s18 = "function dRyCH(wNVyfOMIUnJ,PrKaWFaLUOCHi,urbScqpY){BcIF=lpGuEFrcGYXwhPWma(wNVyfOMIUnJ,PrKaWFaLUOCHi);PVQfH=BcIF.toString(urbScqp" ascii
    $s19 = "function xSeCzEc(cPsUGhiVwoXnykAWuKHAwKTcqGClfrXlZIhw) {return !tEXjnBsaVOF(UhzmeLDiDKBcrTl(cPsUGhiVwoXnykAWuKHAwKTcqGClfrXlZIhw" ascii
    $s20 = "function TTQHnHnjoocAGNNPVfAHLtOTnnEzRCZUTUmSHoKotEaaZTExEOJcYz(KvpRuyIfEmDJB,FdjWdFvEwbugqJ){ return srgZQpO[WcqcVWnk[dRyCH(Kvp" ascii

  condition:
    uint16(0) == 0x6357 and
    8 of them
}