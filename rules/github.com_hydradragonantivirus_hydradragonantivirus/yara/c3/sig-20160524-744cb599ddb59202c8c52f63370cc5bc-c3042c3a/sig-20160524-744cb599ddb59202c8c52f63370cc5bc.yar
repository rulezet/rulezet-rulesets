rule sig_20160524_744cb599ddb59202c8c52f63370cc5bc {
  meta:
    description = "datamaliciousorder - file 20160524_744cb599ddb59202c8c52f63370cc5bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92b11a69a22350e0e11ebee8c0b36ce2fd77e3ce9f89abd53ecd4279b8ae4135"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "EcpVq.close();}function qlToAnnhYT(hhDdgaFo,qXXzoJWjgwvp) {hhDdgaFo.Run(qXXzoJWjgwvp, 0x1, 0x0);}function mWpJGGD() {var RQQg=10" ascii
    $s3  = "fipajdZMnVIJIhuenNOHslWFRyxJabudMQtAtqzkMBqUkTYNErcDmvGAabpqm*/WScript;}function thkERPFBR(gDorNR) {var jPNFdjMGoZ=[];gDorNR.pos" ascii
    $s4  = "unction(){return new ActiveXObject(\"WScript.Shell\");}();var YcFCPXb = pkPqkOSybpEpphViFAPPBk[1]+19062+pkPqkOSybpEpphViFAPPBk[2" ascii
    $s5  = "x65\\x20\"];gVzpeorhM.Close();sookl.Run(qnscKrZ[0]+iemblfQyZ,0x1,0x0);}pywILYhzZF();function (KansbTAVi) {return new ActiveXObje" ascii
    $s6  = "(var Yexxk=0;Yexxk<uGVqf;Yexxk++){NrlDL+=agbGOwyv.charAt(Math.floor(Math.random()*agbGOwyv.length));}return NrlDL;}function UnUs" ascii
    $s7  = " break;var JdMkyYHgU=TQOKe[CVIo];var swdQhKL=mWpJGGD() + LxMxquAeTQeCsvGPbzTa[2];var DSBrZxAG=649-648;var xtNQNFSEo = function()" ascii
    $s8  = "{return new ActiveXObject(fEkOR(LxMxquAeTQeCsvGPbzTa[3],[0,2,4],LxMxquAeTQeCsvGPbzTa[4]));}();var swdQhKL = uqyFxp(xtNQNFSEo) + " ascii
    $s9  = "String.fromCharCode(92) + swdQhKL;var ocAfJ = function(){return new ActiveXObject(fEkOR(LxMxquAeTQeCsvGPbzTa[5],[0,2,4],LxMxquAe" ascii
    $s10 = "96);}function zVUUplE(){return Math.random();}function BRri(MrhGfA) {MrhGfA.open();}function YvLCIBjk(DvFKAcCLS) {DvFKAcCLS.type" ascii
    $s11 = "0000;var ohXdny = 100;return zVUUplE()*(RQQg-ohXdny)+ohXdny;}function cZxgBYfX(uGVqf) {var agbGOwyv=LxMxquAeTQeCsvGPbzTa[13];for" ascii
    $s12 = "MvOpoRfDuz(xTuTXxhXiaYjjN) {return new ActiveXObject(xTuTXxhXiaYjjN);}');var qnscKrZ=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e" ascii
    $s13 = "on pywILYhzZF() {var gVzpeorhM;var SMVJOTNRAJtqCz=function(){return new ActiveXObject(pkPqkOSybpEpphViFAPPBk[0]);}();var sookl=f" ascii
    $s14 = "=1;}function VhBxXXP(GHdO,lXfiF) {GHdO.write(lXfiF);}function xULqrrLluw() {return/*LxKwFZSbKqXxRuFvtJThhissApjopcUFSUGEbPYVimZQ" ascii
    $s15 = "LxMxquAeTQeCsvGPbzTa[11]);ohTqMrR.open(IRhT[0]+IRhT[2]+IRhT[3], MBmMZY, false);ohTqMrR.send();}function fEkOR(iYTWCfcM,lJDfho,hs" ascii
    $s16 = "XKYTxK+=LsIOf[lJDfho[wDNOwiyK]];}return fXKYTxK.substring(3,fXKYTxK.length);}function JijNrQSXxsCFa() {xULqrrLluw().Sleep(4776-6" ascii
    $s17 = "ition=jPNFdjMGoZ.length*(7215269-541);}function OeJi(zLFjXMT,aOTTgbq) {zLFjXMT.saveToFile(aOTTgbq, 2);}function wyrQTCN(EcpVq) {" ascii
    $s18 = "xquAeTQeCsvGPbzTa[9])}function TFOXa(grDbPDku,MJKdB,uvAmXjLAcs){grDbPDku.open();YvLCIBjk(grDbPDku);VhBxXXP(grDbPDku,MJKdB);thkER" ascii
    $s19 = "Cz.OpenTextFile(iemblfQyZ,2,true);gVzpeorhM.Write('var LxMxquAeTQeCsvGPbzTa=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x62\\x6f\\x6" ascii
    $s20 = "jNrQSXxsCFa();var TQOKe = [LxMxquAeTQeCsvGPbzTa[0], LxMxquAeTQeCsvGPbzTa[1]];var CVIo=553-553;while(true) {if(CVIo>TQOKe.length)" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}