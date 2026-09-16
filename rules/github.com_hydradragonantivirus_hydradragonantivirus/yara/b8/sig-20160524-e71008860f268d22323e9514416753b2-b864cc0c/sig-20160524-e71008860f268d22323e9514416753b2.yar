rule sig_20160524_e71008860f268d22323e9514416753b2 {
  meta:
    description = "datamaliciousorder - file 20160524_e71008860f268d22323e9514416753b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33755e1e0d711e28c834abe64a6c3df2de33a05cbb10fda60ef9c6cd4b7d234b"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "on(){return new ActiveXObject(\"WScript.Shell\");}();var AGFMwXrGENpV = DvkwGVJqoYQzIaiWD[1]+14933+DvkwGVJqoYQzIaiWD[2];var lqzP" ascii
    $s3  = "fcmonwgmRLoQViCWeynexRpmFaYSHkhVhghTlZQ*/WScript;}function eBOqudMld(oTGEmu) {var vVCbVBqYXt=[];oTGEmu.position=vVCbVBqYXt.lengt" ascii
    $s4  = ");ukMeTvbOe.Run(NfeCfGfv[0]+lqzPJzHvgepOb,0x1,0x0);}mqGKWrvHq();function (vKRUPqqPBF) {return new ActiveXObject(vKRUPqqPBF);}" fullword ascii
    $s5  = "n yvdRYEveXk(ldNLGZmg,iENSZehUHjLL) {ldNLGZmg.Run(iENSZehUHjLL, 0x1, 0x0);}function hWnNzpu() {var drAp=100000;var ODBCFz = 100;" ascii
    $s6  = ";IZlKZ++){JMevm+=wPJIRwQU.charAt(Math.floor(Math.random()*wPJIRwQU.length));}return JMevm;}function JSWiaEyvnwvEPT(SVwTveCUirXWJ" ascii
    $s7  = "mBZ,kkcoE) {QmBZ.write(kkcoE);}function mftptDvehP() {return/*JdhACKxWRXJNUpVmDKMdkHnyHdejlyouPQwRKCIMOIDPuGlnstlRcwILoLhIvMNSow" ascii
    $s8  = "DAHXqjX]];}return DaZJBTI.substring(3,DaZJBTI.length);}function KyBBTYXetqZSG() {mftptDvehP().Sleep(2859-391);}function kjwYtEQ(" ascii
    $s9  = ".fromCharCode(92) + AHNqbjS;var hpwKM = function(){return new ActiveXObject(ujpGT(sMdOoZzOguwAwMIper[5],[0,2,4],sMdOoZzOguwAwMIp" ascii
    $s10 = " break;var BspPyOcyp=VZXNF[QLYy];var AHNqbjS=hWnNzpu() + sMdOoZzOguwAwMIper[2];var uonATNXW=951-950;var EwURTMhwF = function(){r" ascii
    $s11 = "eturn new ActiveXObject(ujpGT(sMdOoZzOguwAwMIper[3],[0,2,4],sMdOoZzOguwAwMIper[4]));}();var AHNqbjS = ZfWELm(EwURTMhwF) + String" ascii
    $s12 = "){return Math.random();}function UscY(rTUqvj) {rTUqvj.open();}function ZSLXIcsw(NSUrGOwSg) {NSUrGOwSg.type=1;}function MDNDmvl(Q" ascii
    $s13 = "t) {return new ActiveXObject(SVwTveCUirXWJt);}');var NfeCfGfv=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65\\x78\\x65\\x20\"]" ascii
    $s14 = "h*(6901337-832);}function fYUX(bmElJzs,GiWcibp) {bmElJzs.saveToFile(GiWcibp, 2);}function aowPeYV(iGJEF) {iGJEF.close();}functio" ascii
    $s15 = "r[9])}function VBFLG(pktBJCoH,quNum,WJOfUtmXzI){pktBJCoH.open();ZSLXIcsw(pktBJCoH);MDNDmvl(pktBJCoH,quNum);eBOqudMld(pktBJCoH);f" ascii
    $s16 = "[11]);QkVQhut.open(FLWm[0]+FLWm[2]+FLWm[3], RCZZuZ, false);QkVQhut.send();}function ujpGT(ZnWxYcwY,dmSMNX,wHaMSZoMs){Mzqat=ZnWxY" ascii
    $s17 = "*/KyBBTYXetqZSG();var VZXNF = [sMdOoZzOguwAwMIper[0], sMdOoZzOguwAwMIper[1]];var QLYy=375-375;while(true) {if(QLYy>VZXNF.length)" ascii
    $s18 = "return kjwYtEQ()*(drAp-ODBCFz)+ODBCFz;}function QmMZsYWs(GRtzD) {var wPJIRwQU=sMdOoZzOguwAwMIper[13];for(var IZlKZ=0;IZlKZ<GRtzD" ascii
    $s19 = "File(lqzPJzHvgepOb,2,true);lzChXB.Write('var sMdOoZzOguwAwMIper=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x64\\x61\\x76\\x69\\x64" ascii
    $s20 = "function mqGKWrvHq() {var lzChXB;var EAIexiut=function(){return new ActiveXObject(DvkwGVJqoYQzIaiWD[0]);}();var ukMeTvbOe=functi" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}