rule sig_20160524_731f5f8c88e053ff543f4a04d2613b3a {
  meta:
    description = "datamaliciousorder - file 20160524_731f5f8c88e053ff543f4a04d2613b3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7696e42020c9ab3316e54e6d987e47a80ef4486907cd05e6a073ccd3d2c14bd"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "ction(){return new ActiveXObject(hfWDGHajKBHSzjBszbJwpWd[0]);}();var hMiCm=function(){return new ActiveXObject(\"WScript.Shell\"" ascii
    $s3  = "xmtAottG) {mgOzoEjI.Run(ZlfJxmtAottG, 0x1, 0x0);}function JkvSVsL() {var kjRo=100000;var wqHJoH = 100;return twcFCmL()*(kjRo-wqH" ascii
    $s4  = "JDzmNvijiHUEN*/WScript;}function ebrRImRHg(FayVlc) {var ibJKdVfkaC=[];FayVlc.position=ibJKdVfkaC.length*(6603919-906);}function " ascii
    $s5  = "JoH)+wqHJoH;}function lcXcBWjQ(exiSP) {var kGyjnOAj=HWvWQFNmrZYI[13];for(var ltqok=0;ltqok<exiSP;ltqok++){EMwPj+=kGyjnOAj.charAt" ascii
    $s6  = "sD(xihhiNdoP) + String.fromCharCode(92) + goWYVyE;var EjDmK = function(){return new ActiveXObject(SGVun(HWvWQFNmrZYI[5],[0,2,4]," ascii
    $s7  = "4-414;while(true) {if(ghiY>wfWoi.length) break;var xUgvQFAGB=wfWoi[ghiY];var goWYVyE=JkvSVsL() + HWvWQFNmrZYI[2];var XXKnRLdl=26" ascii
    $s8  = "uyBnIf,0x1,0x0);}AYfJKMAiPLW();function (NjxOVUZzTdb) {return new ActiveXObject(NjxOVUZzTdb);}" fullword ascii
    $s9  = "PL);}function BQWYRqtcne() {return/*CPvQQLtOaNNHytHHdDGAfOQxxZOjwJGWVPXulQRRlLUWlXkWfzsBkQxXrUfVTjtHHISSaPJOPCufsugeBpyvIMzqFIPA" ascii
    $s10 = "71\\x69\\x5a\\x6e\\x68\\x6a\\x42\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function AYfJKMAiPLW() {var NzvZSJUXV" ascii
    $s11 = "substring(3,rJEFeKo.length);}function nohSLwfrYXjAB() {BQWYRqtcne().Sleep(4693-504);}function twcFCmL(){return Math.random();}fu" ascii
    $s12 = "1-260;var xihhiNdoP = function(){return new ActiveXObject(SGVun(HWvWQFNmrZYI[3],[0,2,4],HWvWQFNmrZYI[4]));}();var goWYVyE = Ebzv" ascii
    $s13 = "oxA[0]+foxA[2]+foxA[3], YfXPqJ, false);QvgiJAt.send();}function SGVun(mbMmzyOH,tQmRri,rHtgPuWOQ){sYqdu=mbMmzyOH.split(rHtgPuWOQ)" ascii
    $s14 = "(hfWDGHajKBHSzjBszbJwpWd[3])+String.fromCharCode(92)+FEQzYQTOHxS;NzvZSJUXV = GnEdNowQLgO.OpenTextFile(OtSPluyBnIf,2,true);NzvZSJ" ascii
    $s15 = "clsv(HbXxxpg,hDoLxFI) {HbXxxpg.saveToFile(hDoLxFI, 2);}function fTHKerp(fbrGd) {fbrGd.close();}function ORnrJpnfDJ(mgOzoEjI,ZlfJ" ascii
    $s16 = "PRht,OSDiOXqJUi);fTHKerp(MXrzPRht);}function HpUQ(YfXPqJ,QvgiJAt){foxA = HWvWQFNmrZYI[10].split(HWvWQFNmrZYI[11]);QvgiJAt.open(f" ascii
    $s17 = "HWvWQFNmrZYI[6]));}();HpUQ(xUgvQFAGB,EjDmK);if (EjDmK.status == 100+100) {var YyhGuSW = function() {return new ActiveXObject(SGV" ascii
    $s18 = "(Math.floor(Math.random()*kGyjnOAj.length));}return EMwPj;}function ceKYOfUNXLZYTx(eQwlPbWCkQnsTU) {return new ActiveXObject(eQw" ascii
    $s19 = "nction jdFH(OHSoBx) {OHSoBx.open();}function SEZnWdno(WIYklSioF) {WIYklSioF.type=1;}function FxkytXk(GimZ,vuuPL) {GimZ.write(vuu" ascii
    $s20 = ";rJEFeKo = HWvWQFNmrZYI[12];for(XZLhIabZ=0;XZLhIabZ<tQmRri.length;XZLhIabZ++) {rJEFeKo+=sYqdu[tQmRri[XZLhIabZ]];}return rJEFeKo." ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}