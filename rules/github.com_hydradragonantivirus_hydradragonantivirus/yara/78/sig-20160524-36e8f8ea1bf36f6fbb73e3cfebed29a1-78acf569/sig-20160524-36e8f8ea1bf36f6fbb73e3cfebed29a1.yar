rule sig_20160524_36e8f8ea1bf36f6fbb73e3cfebed29a1 {
  meta:
    description = "datamaliciousorder - file 20160524_36e8f8ea1bf36f6fbb73e3cfebed29a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d60b3e730121c1cdc7a0ee98fa39ab53a49757e9c81953f649baaf32c45e94bc"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "n(){return new ActiveXObject(OoRbx[0]);}();var kvsQNArs=function(){return new ActiveXObject(\"WScript.Shell\");}();var hGgmTr = " ascii
    $s3  = "Y = function(){return new ActiveXObject(QFQYA(cfBuenTM[3],[0,2,4],cfBuenTM[4]));}();var kslniud = sAZRpi(GIOqegySY) + String.fro" ascii
    $s4  = "\\x2e\\x65\\x78\\x65\\x20\"];WmOHC.Close();kvsQNArs.Run(GxpeVsPAhl[0]+tHoGpT,0x1,0x0);}ZUlTsVnhtimxhC();function (XSqdWTczZLorEl" ascii
    $s5  = "ction QiUqaTV(gVhLw) {gVhLw.close();}function fLJLIQGWkh(VCQVtBeS,ssgkKazHNVqu) {VCQVtBeS.Run(ssgkKazHNVqu, 0x1, 0x0);}function " ascii
    $s6  = "tFGDwfbGYbVvsTtivDZEzGSTwZEPDgmBOaxPtfoSlurtHrLFzVZmfDpBsojjCBOuCoHVJZUWRHgkpKwVXgu*/WScript;}function sYLNiRZKH(LFTayA) {var VZ" ascii
    $s7  = "TM[13];for(var dxtcC=0;dxtcC<svCIh;dxtcC++){wAXZW+=eMpGkCRA.charAt(Math.floor(Math.random()*eMpGkCRA.length));}return wAXZW;}fun" ascii
    $s8  = "ue) {if(asIi>jmjQn.length) break;var lddojESFz=jmjQn[asIi];var kslniud=XjflQRw() + cfBuenTM[2];var cirHYwaU=704-703;var GIOqegyS" ascii
    $s9  = "mCharCode(92) + kslniud;var tBOVe = function(){return new ActiveXObject(QFQYA(cfBuenTM[5],[0,2,4],cfBuenTM[6]));}();IKOt(lddojES" ascii
    $s10 = "TextFile(tHoGpT,2,true);WmOHC.Write('var cfBuenTM=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x61\\x75\\x6d\\x75\\x2e\\x63\\x6f\\x6d" ascii
    $s11 = "ction izvHWEHeEgHGno(mlBPQrzUkXMoLC) {return new ActiveXObject(mlBPQrzUkXMoLC);}');var GxpeVsPAhl=[\"\\x77\\x73\\x63\\x72\\x69" ascii
    $s12 = "cl.open();xODGpfGb(SvKcLfcl);YrjmoDO(SvKcLfcl,IYkFC);sYLNiRZKH(SvKcLfcl);SrCl(SvKcLfcl,WNVKARsYGa);QiUqaTV(SvKcLfcl);}function I" ascii
    $s13 = "++;}function sAZRpi(bhmFWl){return bhmFWl.ExpandEnvironmentStrings(cfBuenTM[9])}function VLveR(SvKcLfcl,IYkFC,WNVKARsYGa){SvKcLf" ascii
    $s14 = "XjflQRw() {var AWuG=100000;var gVCbAQ = 100;return BRQGaYI()*(AWuG-gVCbAQ)+gVCbAQ;}function CyHodras(svCIh) {var eMpGkCRA=cfBuen" ascii
    $s15 = "Fz,tBOVe);if (tBOVe.status == 100+100) {var Zbuornt = function() {return new ActiveXObject(QFQYA(cfBuenTM[7],[0,2,4],cfBuenTM[8]" ascii
    $s16 = "nuPabpKWxIzTtyNCgjEiCNDxaJQGqVVvSWXawJBiuIMeFR*/PfufdHyixUQJh();var jmjQn = [cfBuenTM[0], cfBuenTM[1]];var asIi=859-859;while(tr" ascii
    $s17 = "qLwEj) {DsYbqLwEj.type=1;}function YrjmoDO(euwR,PAOqa) {euwR.write(PAOqa);}function tejlTYiogC() {return/*TrxnvFKgsOmCPfTCsoYEeB" ascii
    $s18 = "KOt(bMWBkv,CDuEFep){EDij = cfBuenTM[10].split(cfBuenTM[11]);CDuEFep.open(EDij[0]+EDij[2]+EDij[3], bMWBkv, false);CDuEFep.send();" ascii
    $s19 = "lTYiogC().Sleep(5379-634);}function BRQGaYI(){return Math.random();}function cMgB(skwIvr) {skwIvr.open();}function xODGpfGb(DsYb" ascii
    $s20 = "x53\\x44\\x42\\x52\\x69\\x76\\x5a\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function ZUlTsVnhtimxhC() {var WmOHC" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}