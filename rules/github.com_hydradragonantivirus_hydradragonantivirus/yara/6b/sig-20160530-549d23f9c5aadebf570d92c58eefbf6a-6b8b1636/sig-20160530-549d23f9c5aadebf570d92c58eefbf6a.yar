rule sig_20160530_549d23f9c5aadebf570d92c58eefbf6a {
  meta:
    description = "datamaliciousorder - file 20160530_549d23f9c5aadebf570d92c58eefbf6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bcdb92a6ce0e1416f99713a3ba6fbda17f4167e900cd4b1abdd57ed9f80488a"

  strings:
    $s1  = "var VtIzRsMe=function(){return WScript.CreateObject(cWnzM[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function xhPtYWoPshvJd(eVZLfaQ,adspwu){return eVZLfaQ.charAt(adspwu);}" fullword ascii
    $s3  = "function ovzdrFC(FLeRAEPbHxprPL,ebXjiooH,VEmsFmxGw){return String.fromCharCode(FLeRAEPbHxprPL,ebXjiooH,VEmsFmxGw);}" fullword ascii
    $s4  = " 64) QXbmWSrwGbS += y(vhsvTwVjwFyrUbevc);else if (kokvS == 64) QXbmWSrwGbS += RjTAJktYKiNbjIsKL(vhsvTwVjwFyrUbevc, dOKmUCSZepwoW" ascii
    $s5  = "YF);else QXbmWSrwGbS += ovzdrFC(vhsvTwVjwFyrUbevc, dOKmUCSZepwoWYF, ZWjurOsGpFHmQn);} while (pMhLW < iehMYxRBhxMRm.length);retur" ascii
    $s6  = "push(\"D\");yUwbujryKIZlvmBZet.push(\"3\");yUwbujryKIZlvmBZet.push(\"E\");yUwbujryKIZlvmBZet.push(\"F\");yUwbujryKIZlvmBZet.push" ascii
    $s7  = "function UXOTYxWu(){return VtIzRsMe.ExpandEnvironmentStrings(NGKHYg())}" fullword ascii
    $s8  = "function NGKHYg(){return CfxNhnqdmhTCh(cWnzM[9],[1,5,7],cWnzM[10]);}" fullword ascii
    $s9  = "function vKqRhCkPbrUSU(){return CfxNhnqdmhTCh(cWnzM[11],[2,4,8,10],cWnzM[12]);}" fullword ascii
    $s10 = "function RjTAJktYKiNbjIsKL(pKXkvdfOq,AEjla){return String.fromCharCode(pKXkvdfOq,AEjla);}" fullword ascii
    $s11 = "function y(SiuUPYHZGlT){return String.fromCharCode(SiuUPYHZGlT);}" fullword ascii
    $s12 = "function twawjPdavnPCk(ilGUNycxOlkzLo,kSgNMb) {var rtKtWVhjPWM=[cWnzM[15]];ilGUNycxOlkzLo[rtKtWVhjPWM[0]]" fullword ascii
    $s13 = "var rbIwd = sTmnuYGzpsjGSI.createtextfile(VtIzRsMe.ExpandEnvironmentStrings(cWnzM[3]+cWnzM[4])+String.fromCharCode(92)+cWnzM[5]," ascii
    $s14 = "function RKOVGqvEogEZCNijKslxVqKh(ufVZsVJIGemQeITjwqt,NrusFCRgLW){return ufVZsVJIGemQeITjwqt.indexOf(NrusFCRgLW);}" fullword ascii
    $s15 = "function bkOryJePSt(iehMYxRBhxMRm) {var bUWNuDroGBIbsYGTLyL = yUwbujryKIZlvmBZet.join(cWnzM[7]);var vhsvTwVjwFyrUbevc, dOKmUCSZe" ascii
    $s16 = "function yuMjYQZu(){return CfxNhnqdmhTCh(cWnzM[13],[0,3,6],cWnzM[14]);}" fullword ascii
    $s17 = "function bkOryJePSt(iehMYxRBhxMRm) {var bUWNuDroGBIbsYGTLyL = yUwbujryKIZlvmBZet.join(cWnzM[7]);var vhsvTwVjwFyrUbevc, dOKmUCSZe" ascii
    $s18 = "var sTmnuYGzpsjGSI=function(){return new ActiveXObject(cWnzM[1]);}();" fullword ascii
    $s19 = "function CfxNhnqdmhTCh(kZFwyPsZ,uCatYFnk,KShcQzuTzyuXx){XYVQoG=kZFwyPsZ.split(KShcQzuTzyuXx);eaHqBv = cWnzM[0];for(cqkzu=0;cqkzu" ascii
    $s20 = "<uCatYFnk.length;cqkzu++) {eaHqBv+=XYVQoG[uCatYFnk[cqkzu]];}return eaHqBv.substring(3,eaHqBv.length);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}