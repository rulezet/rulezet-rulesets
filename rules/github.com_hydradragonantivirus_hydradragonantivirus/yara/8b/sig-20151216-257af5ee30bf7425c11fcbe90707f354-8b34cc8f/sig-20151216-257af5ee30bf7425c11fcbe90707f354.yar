rule sig_20151216_257af5ee30bf7425c11fcbe90707f354 {
  meta:
    description = "datamaliciousorder - file 20151216_257af5ee30bf7425c11fcbe90707f354.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c5137f90ec9f4ea082c109e36c06aaa91a9f02669d82d953d16ea53a012bd80"

  strings:
    $s1  = ".pow(Math.cos(397), 2) - 1)));} YHCKjyuhk[iKaxwmdmqSJ]++;}iKaxwmdmqSJ++;} return lALPtidgzWN}" fullword ascii
    $s2  = "function cBNMnGMeMizcsqkGE(CCREy){lALPtidgzWN= '';iKaxwmdmqSJ=Math.round((Math.pow(Math.sin(375), 2) + Math.pow(Math.cos(375), 2" ascii
    $s3  = ") - 1));while(true){if (iKaxwmdmqSJ >= (1131+345)/246){break;}YHCKjyuhk[iKaxwmdmqSJ]=Math.round((Math.pow(Math.sin(712), 2) + Ma" ascii
    $s4  = "th.pow(Math.cos(712), 2) - 1)); while(true) { if(YHCKjyuhk[iKaxwmdmqSJ] > CCREy[iKaxwmdmqSJ].length-(-623+992)/369) { break; } i" ascii
    $s5  = "function cBNMnGMeMizcsqkGE(CCREy){lALPtidgzWN= '';iKaxwmdmqSJ=Math.round((Math.pow(Math.sin(375), 2) + Math.pow(Math.cos(375), 2" ascii
    $s6  = "kXxjDzhsIUFJqslYQWHfdxphUzbOtioecjaJ([CCREy[iKaxwmdmqSJ][YHCKjyuhk[iKaxwmdmqSJ]]], Math.round((Math.pow(Math.sin(397), 2) + Math" ascii
    $s7  = "function oyBznQLrUhaObBUrnqkXxjDzhsIUFJqslYQWHfdxphUzbOtioecjaJ(AdHVKUpQIOOvP,iuCOmlflDOyeeR){ return oLUHQdr[GqZInWRi[MTfnU(AdH" ascii
    $s8  = "function APHXnVB(joGFeNGROdbgKCvCUJIYHBdmdgeRjiITSztC) {return !JyBvMastkhY(IcsAmfISKNNMCGS(joGFeNGROdbgKCvCUJIYHBdmdgeRjiITSztC" ascii
    $s9  = "function oyBznQLrUhaObBUrnqkXxjDzhsIUFJqslYQWHfdxphUzbOtioecjaJ(AdHVKUpQIOOvP,iuCOmlflDOyeeR){ return oLUHQdr[GqZInWRi[MTfnU(AdH" ascii
    $s10 = "function mAocxjejHTcmwwF(CNXrbvKmFnnnRlBsj,dHhmZxjOUWTwzeycbOfXJYVtsBWzqffeRz,MfZRucFodHYWrhMffclXgYsPoHpOboqaRsG){eval(CNXrbvKm" ascii
    $s11 = "function mAocxjejHTcmwwF(CNXrbvKmFnnnRlBsj,dHhmZxjOUWTwzeycbOfXJYVtsBWzqffeRz,MfZRucFodHYWrhMffclXgYsPoHpOboqaRsG){eval(CNXrbvKm" ascii
    $s12 = "function JyBvMastkhY(ChswKpZZGmOUcE) {return isNaN(ChswKpZZGmOUcE);}" fullword ascii
    $s13 = "var y = new Array();y[0]=[];y[0][0]='d';y[0][1]='a';y[0][2]='d';y[0][3]='a';y[0][4]='46';y[0][5]='3d';y[0][6]='42';y[0][7]='14';" ascii
    $s14 = "function jgHerznIpZtMNzvsK(HdpcOJrPpQ,ABXhDdrJjy) {return parseInt(HdpcOJrPpQ,ABXhDdrJjy);}" fullword ascii
    $s15 = "function LPSSyKXNmwzb(kvFVTgGpmpoaK) {return isFinite(kvFVTgGpmpoaK);}" fullword ascii
    $s16 = "c);return NREty;}" fullword ascii
    $s17 = "function IcsAmfISKNNMCGS(oDNzDbeEYWdEUQqgyUn) {return parseFloat(oDNzDbeEYWdEUQqgyUn);}" fullword ascii
    $s18 = "function APHXnVB(joGFeNGROdbgKCvCUJIYHBdmdgeRjiITSztC) {return !JyBvMastkhY(IcsAmfISKNNMCGS(joGFeNGROdbgKCvCUJIYHBdmdgeRjiITSztC" ascii
    $s19 = "function F(JLyLGKkRCZCW,NxqkdvQPplVaOa){JLyLGKkRCZCW.push(NxqkdvQPplVaOa);}" fullword ascii
    $s20 = ",'(','_','N','V','#','W','D','f','Q','P','D','{','6','X','n','H','0','Y','H','!','T','Z','i','(','g','i','6',' ','[','C',String." ascii

  condition:
    uint16(0) == 0x7147 and
    8 of them
}