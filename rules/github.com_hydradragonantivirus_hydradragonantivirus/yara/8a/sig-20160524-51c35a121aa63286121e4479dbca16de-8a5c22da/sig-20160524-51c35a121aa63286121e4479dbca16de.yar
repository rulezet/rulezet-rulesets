rule sig_20160524_51c35a121aa63286121e4479dbca16de {
  meta:
    description = "datamaliciousorder - file 20160524_51c35a121aa63286121e4479dbca16de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cceb1d310cbd2c3e1cb54a43c99ba8641bdd72211b4bc4fc8c8094383ff43d11"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "tCXWSYkyRmmUn=function(){return new ActiveXObject(\"WScript.Shell\");}();var zDurwKXOe = YdRpEv[1]+10387+YdRpEv[2];var zGOKt=tCX" ascii
    $s3  = "tring.fromCharCode(92) + ezZGqaI;var oXyST = function(){return new ActiveXObject(bcuro(FnbKJ[5],[0,2,4],FnbKJ[6]));}();uXja(EaZy" ascii
    $s4  = "sJzH) {QsJzH.close();}function YgdHnDZTwU(lYlvmbRZ,aEZYYPUjhmpY) {lYlvmbRZ.Run(aEZYYPUjhmpY, 0x1, 0x0);}function HjrbyFd() {var " ascii
    $s5  = "LWxxUvtdYGvYOAkRIBOVzKPUExpbONVaxfLdvxqWbmPPhzMveHnYKIWjraSpRJHbChtD*/WScript;}function imUdEbeKD(equxRJ) {var reoOoOUJvv=[];equ" ascii
    $s6  = "0\"];KyPRwr.Close();tCXWSYkyRmmUn.Run(pWSXlXYOX[0]+zGOKt,0x1,0x0);}SBDuLQBcrfpDda();function (PbVqFdjR) {return new ActiveXObjec" ascii
    $s7  = "Zh=0;ehkZh<BruCZ;ehkZh++){TqrGd+=UmOVzpeg.charAt(Math.floor(Math.random()*UmOVzpeg.length));}return TqrGd;}function NJJnGLVwDdgu" ascii
    $s8  = "57;var YyHeJyxYY = function(){return new ActiveXObject(bcuro(FnbKJ[3],[0,2,4],FnbKJ[4]));}();var ezZGqaI = qrrqAG(YyHeJyxYY) + S" ascii
    $s9  = "c=168-168;while(true) {if(YYUc>khqSU.length) break;var EaZyWwHFc=khqSU[YYUc];var ezZGqaI=HjrbyFd() + FnbKJ[2];var VYgnGvsT=458-4" ascii
    $s10 = "xRJ.position=reoOoOUJvv.length*(6652312-372);}function Fayq(VQIrPNK,QKTREFO) {VQIrPNK.saveToFile(QKTREFO, 2);}function NbYDJWO(Q" ascii
    $s11 = "YkyRmmUn.ExpandEnvironmentStrings(YdRpEv[3])+String.fromCharCode(92)+zDurwKXOe;KyPRwr = dVWnIGohLW.OpenTextFile(zGOKt,2,true);Ky" ascii
    $s12 = "}function qrrqAG(ZpHFhw){return ZpHFhw.ExpandEnvironmentStrings(FnbKJ[9])}function kIOvc(lddJTssV,FmZfS,RkfEKLnpYN){lddJTssV.ope" ascii
    $s13 = "krVA=100000;var zyYHBF = 100;return doyWQMe()*(krVA-zyYHBF)+zyYHBF;}function gWtVjrGi(BruCZ) {var UmOVzpeg=FnbKJ[13];for(var ehk" ascii
    $s14 = "pc(PmcBVDBSXyXRRA) {return new ActiveXObject(PmcBVDBSXyXRRA);}');var pWSXlXYOX=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65" ascii
    $s15 = "zLAw,xFJKiTl){Olnx = FnbKJ[10].split(FnbKJ[11]);xFJKiTl.open(Olnx[0]+Olnx[2]+Olnx[3], SazLAw, false);xFJKiTl.send();}function bc" ascii
    $s16 = "WwHFc,oXyST);if (oXyST.status == 100+100) {var LWRiJVJ = function() {return new ActiveXObject(bcuro(FnbKJ[7],[0,2,4],FnbKJ[8]));" ascii
    $s17 = "4\\x45\\x4d\\x50\\x25\"];function SBDuLQBcrfpDda() {var KyPRwr;var dVWnIGohLW=function(){return new ActiveXObject(YdRpEv[0]);}()" ascii
    $s18 = "(4810-869);}function doyWQMe(){return Math.random();}function qTVg(qSzWvR) {qSzWvR.open();}function LsDvpMnJ(xWwnVnEkT) {xWwnVnE" ascii
    $s19 = "kT.type=1;}function EIfdmie(LebM,CwLhM) {LebM.write(CwLhM);}function YZvkuHWkWq() {return/*eQBEFtHCKNoPeoSwZPtbgGqKLIFbykNgGfKDT" ascii
    $s20 = "n();LsDvpMnJ(lddJTssV);EIfdmie(lddJTssV,FmZfS);imUdEbeKD(lddJTssV);Fayq(lddJTssV,RkfEKLnpYN);NbYDJWO(lddJTssV);}function uXja(Sa" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}