rule sig_20160524_0b3a5780b1ae2f38e926ec61eaf387b2 {
  meta:
    description = "datamaliciousorder - file 20160524_0b3a5780b1ae2f38e926ec61eaf387b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ccac8a9f9041ad77f2f16a4805e839b7a79e3d02555b7d80467a69ef13c7edb"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "iWbCMdAEB(RMTARxLh,hSautKeMFiNh) {RMTARxLh.Run(hSautKeMFiNh, 0x1, 0x0);}function IagMTfB() {var taqr=100000;var WvhIGW = 100;ret" ascii
    $s3  = "ction(){return new ActiveXObject(rygWhFbOWpEKAfzijLbvSgv[0]);}();var BNVtXPn=function(){return new ActiveXObject(\"WScript.Shell" ascii
    $s4  = "sRcrqVWahhyKqHUoPZVcdoOTefjfpDsDLnaG*/WScript;}function uLjNHtvBd(RTlFLm) {var kLfMovFfQg=[];RTlFLm.position=kLfMovFfQg.length*(" ascii
    $s5  = "oT.Close();BNVtXPn.Run(CHFwkwmKqaqdz[0]+IXLXz,0x1,0x0);}PZIQrVlcdp();function (zEPPIFY) {return new ActiveXObject(zEPPIFY);}" fullword ascii
    $s6  = "QyNlDF.open(ZCdw[0]+ZCdw[2]+ZCdw[3], UDhXdH, false);iQyNlDF.send();}function RakEh(MSUWWZWD,aKWSYD,EjnJhtTIp){eNffi=MSUWWZWD.spl" ascii
    $s7  = "j;zWLOZ++){LIkLv+=uIBziQOK.charAt(Math.floor(Math.random()*uIBziQOK.length));}return LIkLv;}function jSOtLOIifGgViq(MrmtFGjMrCqT" ascii
    $s8  = ",hQPVe) {fYaV.write(hQPVe);}function waueXvQANf() {return/*vVXrYmgOUZsJYfnMEcVkCQVNmTsIyiREFixPySPYvLXspJAIxnEfLtNvxBgOzJoXipqhr" ascii
    $s9  = "gMTfB() + aBNZpQvQnScjnYrWvKkMuI[2];var yTuIsZhD=329-328;var tenYtftFL = function(){return new ActiveXObject(RakEh(aBNZpQvQnScjn" ascii
    $s10 = "lubQ]];}return pvURzct.substring(3,pvURzct.length);}function PnsezigrneCkf() {waueXvQANf().Sleep(3376-570);}function nQkgPpj(){r" ascii
    $s11 = "urn nQkgPpj()*(taqr-WvhIGW)+WvhIGW;}function AejVVLPj(qglgj) {var uIBziQOK=aBNZpQvQnScjnYrWvKkMuI[13];for(var zWLOZ=0;zWLOZ<qglg" ascii
    $s12 = "bOWpEKAfzijLbvSgv[3])+String.fromCharCode(92)+DgODwX;JgrmemJoT = CFmEFNFTYsGW.OpenTextFile(IXLXz,2,true);JgrmemJoT.Write('var aB" ascii
    $s13 = "Zo) {return new ActiveXObject(MrmtFGjMrCqTZo);}');var CHFwkwmKqaqdz=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65\\x78\\x65" ascii
    $s14 = "6c\\x42\\x56\\x59\\x6a\\x76\\x42\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function PZIQrVlcdp() {var JgrmemJoT;" ascii
    $s15 = "JhJQVITc);wCSBXpI(mVjRJMts);}function aXxH(UDhXdH,iQyNlDF){ZCdw = aBNZpQvQnScjnYrWvKkMuI[10].split(aBNZpQvQnScjnYrWvKkMuI[11]);i" ascii
    $s16 = "], aBNZpQvQnScjnYrWvKkMuI[1]];var HslC=650-650;while(true) {if(HslC>SCdBq.length) break;var djRtPgZup=SCdBq[HslC];var iidvmWe=Ia" ascii
    $s17 = "Vr = function(){return new ActiveXObject(RakEh(aBNZpQvQnScjnYrWvKkMuI[5],[0,2,4],aBNZpQvQnScjnYrWvKkMuI[6]));}();aXxH(djRtPgZup," ascii
    $s18 = "EKwVr);if (EKwVr.status == 100+100) {var QipvzhK = function() {return new ActiveXObject(RakEh(aBNZpQvQnScjnYrWvKkMuI[7],[0,2,4]," ascii
    $s19 = "eturn Math.random();}function nKMJ(fiZIlW) {fiZIlW.open();}function uHLkOBkL(ARNJuAYQQ) {ARNJuAYQQ.type=1;}function bWrFsmX(fYaV" ascii
    $s20 = "6857744-960);}function oBIR(MOhbeag,HVZXipW) {MOhbeag.saveToFile(HVZXipW, 2);}function wCSBXpI(arrrf) {arrrf.close();}function V" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}