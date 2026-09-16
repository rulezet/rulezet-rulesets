rule sig_20160524_efdbf8d18fdf7325732df80ab5efdd10 {
  meta:
    description = "datamaliciousorder - file 20160524_efdbf8d18fdf7325732df80ab5efdd10.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c819da6a705eb39857673ffd9584689de8fccaf593df0c27fac7eace81963c5"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "LfBonQlLfBJXEKbkDrSjtSmfTmPLuYFkNbnpsSTlZwaJblOVpkOHiQecxeq*/WScript;}function cefJCEkTZ(tTDCng) {var tYGvsyoJhO=[];tTDCng.posit" ascii
    $s3  = "yIe.close();}function YaAwcpFYse(oiYCtZAx,nUdZMTkTjsbs) {oiYCtZAx.Run(nUdZMTkTjsbs, 0x1, 0x0);}function sdtWzJE() {var pgwV=1000" ascii
    $s4  = "DEMWtgpMl[0]);}();var CgkgWNmYppsyMo=function(){return new ActiveXObject(\"WScript.Shell\");}();var DFpFPlkNRTTTIT = xnCKtlaHJtQ" ascii
    $s5  = "x20\"];dksecUzRTbFXv.Close();CgkgWNmYppsyMo.Run(OVsYoJobLsW[0]+AtKSSRVRw,0x1,0x0);}zUZHVxwLLrw();function (mdYjQFnfs) {return ne" ascii
    $s6  = "LY=0;rTJLY<LOyjX;rTJLY++){iEdPm+=RmQgDTGZ.charAt(Math.floor(Math.random()*RmQgDTGZ.length));}return iEdPm;}function JpiixfbwtEVb" ascii
    $s7  = "fV[4]));}();var XoiyFYR = QWELRf(uLOdTTfwb) + String.fromCharCode(92) + XoiyFYR;var XTSFz = function(){return new ActiveXObject(" ascii
    $s8  = "VWcBAsfV[1]];var THzU=165-165;while(true) {if(THzU>yHtwh.length) break;var hhyqGTuYK=yHtwh[THzU];var XoiyFYR=sdtWzJE() + YsuOriV" ascii
    $s9  = "ring.fromCharCode(92)+DFpFPlkNRTTTIT;dksecUzRTbFXv = bYBfNyM.OpenTextFile(AtKSSRVRw,2,true);dksecUzRTbFXv.Write('var YsuOriVWcBA" ascii
    $s10 = "on() {return new ActiveXObject(DYiUa(YsuOriVWcBAsfV[7],[0,2,4],YsuOriVWcBAsfV[8]));}();SOJdM(FcZMyzf,XTSFz.ResponseBody,XoiyFYR)" ascii
    $s11 = "00;var mScKkP = 100;return UbDCXjf()*(pgwV-mScKkP)+mScKkP;}function MPiAlCFf(LOyjX) {var RmQgDTGZ=YsuOriVWcBAsfV[13];for(var rTJ" ascii
    $s12 = "10].split(YsuOriVWcBAsfV[11]);BkgPVyz.open(kxDd[0]+kxDd[2]+kxDd[3], FWRHMz, false);BkgPVyz.send();}function DYiUa(dFCbgLdl,SSWHy" ascii
    $s13 = ");}function UbDCXjf(){return Math.random();}function FBGW(QcwobA) {QcwobA.open();}function lSCteTnF(FdzJUHeEA) {FdzJUHeEA.type=1" ascii
    $s14 = "ion=tYGvsyoJhO.length*(8872662-153);}function DwPe(tFWgZKH,gpHAOGX) {tFWgZKH.saveToFile(gpHAOGX, 2);}function GrQDFzl(XAyIe) {XA" ascii
    $s15 = "WcBAsfV[2];var BDPzYbGd=400-399;var uLOdTTfwb = function(){return new ActiveXObject(DYiUa(YsuOriVWcBAsfV[3],[0,2,4],YsuOriVWcBAs" ascii
    $s16 = "LbZt+=WBuBT[SSWHyT[VqaIqJVN]];}return dpULbZt.substring(3,dpULbZt.length);}function UAwCsjRtjQNUF() {wsigRqIull().Sleep(4083-340" ascii
    $s17 = ";}function ruMEsni(Jvap,WMAgU) {Jvap.write(WMAgU);}function wsigRqIull() {return/*hVWBJTRkUZnLTAccjhBHWfEAMfBeIskrqFYMOcIoIvGvcW" ascii
    $s18 = "25\\x54\\x45\\x4d\\x50\\x25\"];function zUZHVxwLLrw() {var dksecUzRTbFXv;var bYBfNyM=function(){return new ActiveXObject(xnCKtla" ascii
    $s19 = "DX(IXFVGIELHfedcO) {return new ActiveXObject(IXFVGIELHfedcO);}');var OVsYoJobLsW=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x6" ascii
    $s20 = "EnvironmentStrings(YsuOriVWcBAsfV[9])}function SOJdM(QNkhQPqO,ilzTJ,aqgMIVOhfR){QNkhQPqO.open();lSCteTnF(QNkhQPqO);ruMEsni(QNkhQ" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}