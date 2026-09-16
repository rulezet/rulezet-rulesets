rule sig_20160523_447ae2d0096de2b9a629683e78317235 {
  meta:
    description = "datamaliciousorder - file 20160523_447ae2d0096de2b9a629683e78317235.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41fc7b9ae6cfc33afbb1e3f6ef06e595b4138facf19ccd45d822dda59caa1254"

  strings:
    $s1  = "function QbdPVLiGiF() {return/*rMJOnCJbQmvKzwzgkgYcebPjjnDmkxCKFpUDfGUDJUkLysWYrGEWPbCWNAsXadquVlFpcOIWuQQvMbbnikIvLukeKeSpwgPTW" ascii
    $s2  = "function cYDEcSedZI(qDpZBIJZ,NoZDxerFPETq) {qDpZBIJZ.Run(NoZDxerFPETq, 0x1, 0x0);}" fullword ascii
    $s3  = "function idxLTljz(SXoBq) {var msJjnyCL=BkNBhAGgsf[13];for(var LCDJw=0;LCDJw<SXoBq;LCDJw++){EmBOD+=msJjnyCL.charAt(Math.floor(Mat" ascii
    $s4  = "function idxLTljz(SXoBq) {var msJjnyCL=BkNBhAGgsf[13];for(var LCDJw=0;LCDJw<SXoBq;LCDJw++){EmBOD+=msJjnyCL.charAt(Math.floor(Mat" ascii
    $s5  = "function ePfkl(xBVKnknK,guUbB,IVSmfZKKjh){qnSY(xBVKnknK);jKHRVivK(xBVKnknK);ruQkqiK(xBVKnknK,guUbB);AyPnFKpHt(xBVKnknK);AIcr(xBV" ascii
    $s6  = "f.length;itrKdJmf++) {YVYhtBG+=TXWHR[JldFXf[itrKdJmf]];}return YVYhtBG.substring(3,YVYhtBG.length);}" fullword ascii
    $s7  = "function mNGmbnLFqbqIb() {QbdPVLiGiF().Sleep(2462935-589);}" fullword ascii
    $s8  = "function jKHRVivK(hrhXhkdXD) {hrhXhkdXD.type=1;}" fullword ascii
    $s9  = "function OTCt(KyTnAQ,tBkBTeJ){Masf = BkNBhAGgsf[10].split(BkNBhAGgsf[11]);tBkBTeJ.open(Masf[0]+Masf[2]+Masf[3], KyTnAQ, false);t" ascii
    $s10 = "function QbdPVLiGiF() {return/*rMJOnCJbQmvKzwzgkgYcebPjjnDmkxCKFpUDfGUDJUkLysWYrGEWPbCWNAsXadquVlFpcOIWuQQvMbbnikIvLukeKeSpwgPTW" ascii
    $s11 = "function ruQkqiK(zJxz,tiXnk) {zJxz.write(tiXnk);}" fullword ascii
    $s12 = "h.random()*msJjnyCL.length));}return EmBOD;}" fullword ascii
    $s13 = "function AyPnFKpHt(TUfTnL) {var FoEzelXjpc=[];TUfTnL.position=FoEzelXjpc.length*(9871656-142);}" fullword ascii
    $s14 = "function QugTpf(SunHyX){return SunHyX.ExpandEnvironmentStrings(BkNBhAGgsf[9])}" fullword ascii
    $s15 = "function bdzkQ(wGiaafkh,JldFXf,mUKsztNKR){TXWHR=wGiaafkh.split(mUKsztNKR);YVYhtBG = BkNBhAGgsf[12];for(itrKdJmf=0;itrKdJmf<JldFX" ascii
    $s16 = "function OTCt(KyTnAQ,tBkBTeJ){Masf = BkNBhAGgsf[10].split(BkNBhAGgsf[11]);tBkBTeJ.open(Masf[0]+Masf[2]+Masf[3], KyTnAQ, false);t" ascii
    $s17 = "function gaWuVvQ(awOMS) {awOMS.close();}" fullword ascii
    $s18 = "function bdzkQ(wGiaafkh,JldFXf,mUKsztNKR){TXWHR=wGiaafkh.split(mUKsztNKR);YVYhtBG = BkNBhAGgsf[12];for(itrKdJmf=0;itrKdJmf<JldFX" ascii
    $s19 = "function aBiEPKf() {var TeUS=100000;var qQDBFd = 100;return dEitxiI()*(TeUS-qQDBFd)+qQDBFd;}" fullword ascii
    $s20 = "function HdSty(SunHyX){return new ActiveXObject(SunHyX);}" fullword ascii

  condition:
    uint16(0) == 0x1127 and
    8 of them
}