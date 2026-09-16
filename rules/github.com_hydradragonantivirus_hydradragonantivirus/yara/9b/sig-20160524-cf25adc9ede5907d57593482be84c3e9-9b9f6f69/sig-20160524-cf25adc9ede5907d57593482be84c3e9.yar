rule sig_20160524_cf25adc9ede5907d57593482be84c3e9 {
  meta:
    description = "datamaliciousorder - file 20160524_cf25adc9ede5907d57593482be84c3e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "460ef189b7b5f56849eee6faa56f3555d19c2e863e32283822a8de362c18e0ca"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "unction(){return new ActiveXObject(\"WScript.Shell\");}();var ANzMELYNKCoOX = xokkZLICsFGIbWHLUshnHH[1]+10968+xokkZLICsFGIbWHLUs" ascii
    $s3  = "Y) {LMSaUbEi.Run(nvFpvEoWxNxY, 0x1, 0x0);}function BTcKFzA() {var pyGn=100000;var jzKuEA = 100;return uoHlHnn()*(pyGn-jzKuEA)+jz" ascii
    $s4  = "fpYdrl*/WScript;}function sLPTNCGAK(ebXhUM) {var BBeXfTmuaF=[];ebXhUM.position=BBeXfTmuaF.length*(4578067-285);}function zpfL(tt" ascii
    $s5  = "arAt(Math.floor(Math.random()*elRcbYXO.length));}return ijyuD;}function ZNYwBRcQNkCBDP(eongOoJgiokpuy) {return new ActiveXObject" ascii
    $s6  = "1-311;while(true) {if(ObSZ>bvOoJ.length) break;var IXJIhOObn=bvOoJ[ObSZ];var eNuSRkA=BTcKFzA() + mLCTgbqqDKjCmRZyIDwrRDD[2];var " ascii
    $s7  = "wrRDD[4]));}();var eNuSRkA = vpsCVY(CSRUCbggN) + String.fromCharCode(92) + eNuSRkA;var gEKgX = function(){return new ActiveXObje" ascii
    $s8  = "KJbRJ,xbuszzo) {ttKJbRJ.saveToFile(xbuszzo, 2);}function EOYlLPE(vEzVF) {vEzVF.close();}function CrdZwqHpET(LMSaUbEi,nvFpvEoWxNx" ascii
    $s9  = "ruOy = YsSxtjtAtINqs.OpenTextFile(skedZOSuRXKyVn,2,true);TgKJNruOy.Write('var mLCTgbqqDKjCmRZyIDwrRDD=[\"\\x68\\x74\\x74\\x70\\x" ascii
    $s10 = "pzlDvauo=234-233;var CSRUCbggN = function(){return new ActiveXObject(BhewX(mLCTgbqqDKjCmRZyIDwrRDD[3],[0,2,4],mLCTgbqqDKjCmRZyID" ascii
    $s11 = "{var exdzZRV = function() {return new ActiveXObject(BhewX(mLCTgbqqDKjCmRZyIDwrRDD[7],[0,2,4],mLCTgbqqDKjCmRZyIDwrRDD[8]));}();Cg" ascii
    $s12 = "qDKjCmRZyIDwrRDD[12];for(IJYzslSS=0;IJYzslSS<EgBnxV.length;IJYzslSS++) {bLLXNui+=qsmsu[EgBnxV[IJYzslSS]];}return bLLXNui.substri" ascii
    $s13 = "cGdO(wCDjZh) {wCDjZh.open();}function dVPHxYxM(cPcIJskgL) {cPcIJskgL.type=1;}function iYsZgXd(SNoz,hazqk) {SNoz.write(hazqk);}fu" ascii
    $s14 = "OSuRXKyVn,0x1,0x0);}ICwpwuKXJ();function (qjBfJ) {return new ActiveXObject(qjBfJ);}" fullword ascii
    $s15 = "ng(3,bLLXNui.length);}function CfIwhXNpkJUIK() {XJxWbChOoe().Sleep(5640-672);}function uoHlHnn(){return Math.random();}function " ascii
    $s16 = "KuEA;}function LzlSiIqt(XADvF) {var elRcbYXO=mLCTgbqqDKjCmRZyIDwrRDD[13];for(var vcGNR=0;vcGNR<XADvF;vcGNR++){ijyuD+=elRcbYXO.ch" ascii
    $s17 = "ion vpsCVY(QNZXdC){return QNZXdC.ExpandEnvironmentStrings(mLCTgbqqDKjCmRZyIDwrRDD[9])}function CgDJG(QCZEJlqU,QOAzO,WUUKVsbhxk){" ascii
    $s18 = "on ICwpwuKXJ() {var TgKJNruOy;var YsSxtjtAtINqs=function(){return new ActiveXObject(xokkZLICsFGIbWHLUshnHH[0]);}();var mxptMfA=f" ascii
    $s19 = "DJG(exdzZRV,gEKgX.ResponseBody,eNuSRkA);}if (pzlDvauo > 0){try {CrdZwqHpET(CSRUCbggN,eNuSRkA);} catch(e) {}break;};ObSZ++;}funct" ascii
    $s20 = "P[3], VCAYfi, false);ZdWKUWR.send();}function BhewX(HcXLZtEl,EgBnxV,BkaSPUozc){qsmsu=HcXLZtEl.split(BkaSPUozc);bLLXNui = mLCTgbq" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}