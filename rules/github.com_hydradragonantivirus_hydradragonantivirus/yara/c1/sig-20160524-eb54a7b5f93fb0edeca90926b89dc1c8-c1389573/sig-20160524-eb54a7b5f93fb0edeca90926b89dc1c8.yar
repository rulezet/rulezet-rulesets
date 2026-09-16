rule sig_20160524_eb54a7b5f93fb0edeca90926b89dc1c8 {
  meta:
    description = "datamaliciousorder - file 20160524_eb54a7b5f93fb0edeca90926b89dc1c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08597c6b26a759169be9fc2bf70ea08e64616544b3c3c2a17c5de3d3df79ae7c"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "\\x74\\x2e\\x65\\x78\\x65\\x20\"];CPqNQigDIwU.Close();zsZOHmNoO.Run(uXHMGUPwFW[0]+eUrTG,0x1,0x0);}jdKBrkdunV();function (WBZoilV" ascii
    $s3  = "HObCc(aNXGG) {aNXGG.close();}function iBMeqzksQC(uUNWgJMt,NkSeguKNEMsH) {uUNWgJMt.Run(NkSeguKNEMsH, 0x1, 0x0);}function oemnRml(" ascii
    $s4  = "iWrUKkfJdBFaYnrYHlniPOQIHMadVzpzQSHAejAlWpTleDlELRzXGwitXklxxzfpsiQzsBPgJxbP*/WScript;}function UdkrqkoYo(MDmaBb) {var MlUiChJVo" ascii
    $s5  = "mentStrings(LwfPkpZKrwFCYbDHhIFT[9])}function HQbRE(elbHzYrD,rNRDz,BftpOnjExV){elbHzYrD.open();ATYiJQqt(elbHzYrD);OfkLkee(elbHzY" ascii
    $s6  = "rD,rNRDz);UdkrqkoYo(elbHzYrD);mNax(elbHzYrD,BftpOnjExV);sFHObCc(elbHzYrD);}function LLcf(lAzytr,pewbvDe){WpYD = LwfPkpZKrwFCYbDH" ascii
    $s7  = "DHhIFT[13];for(var BfJmc=0;BfJmc<rdORS;BfJmc++){GotTD+=GUPXaBcr.charAt(Math.floor(Math.random()*GUPXaBcr.length));}return GotTD;" ascii
    $s8  = "b>ylyIz.length) break;var GqlTIlbNx=ylyIz[DIlb];var eVObiMX=oemnRml() + LwfPkpZKrwFCYbDHhIFT[2];var chRKCoba=999-998;var inKsYqI" ascii
    $s9  = "u(inKsYqIKD) + String.fromCharCode(92) + eVObiMX;var UAlXV = function(){return new ActiveXObject(BeXKi(LwfPkpZKrwFCYbDHhIFT[5],[" ascii
    $s10 = "y=[];MDmaBb.position=MlUiChJVoy.length*(158037-138);}function mNax(vJrOCfs,JycIUDX) {vJrOCfs.saveToFile(JycIUDX, 2);}function sF" ascii
    $s11 = "qhikAkLUSGGlqQzPNo[3])+String.fromCharCode(92)+rMryIZDR;CPqNQigDIwU = qkjkLFKxW.OpenTextFile(eUrTG,2,true);CPqNQigDIwU.Write('va" ascii
    $s12 = "().Sleep(4279-886);}function jokJemh(){return Math.random();}function UgGa(sNAaWW) {sNAaWW.open();}function ATYiJQqt(HCpczpOiQ) " ascii
    $s13 = "0,2,4],LwfPkpZKrwFCYbDHhIFT[6]));}();LLcf(GqlTIlbNx,UAlXV);if (UAlXV.status == 100+100) {var jwEnfCe = function() {return new Ac" ascii
    $s14 = "{HCpczpOiQ.type=1;}function OfkLkee(Nqfq,dpZTm) {Nqfq.write(dpZTm);}function XlwxFoZutV() {return/*IjFDCdhlkMqrLvZUMRzrqkIJdmTsc" ascii
    $s15 = "hIFT[10].split(LwfPkpZKrwFCYbDHhIFT[11]);pewbvDe.open(WpYD[0]+WpYD[2]+WpYD[3], lAzytr, false);pewbvDe.send();}function BeXKi(yVK" ascii
    $s16 = "}function RKxqWwXDpxFOcY(mWOMkyEXsucqbi) {return new ActiveXObject(mWOMkyEXsucqbi);}');var uXHMGUPwFW=[\"\\x77\\x73\\x63\\x72\\x" ascii
    $s17 = ";TEYdrFnU++) {kPsKKmv+=hMnZv[KCIgzw[TEYdrFnU]];}return kPsKKmv.substring(3,kPsKKmv.length);}function dnYEKQFgqyuxh() {XlwxFoZutV" ascii
    $s18 = ") {var lchw=100000;var uzCllm = 100;return jokJemh()*(lchw-uzCllm)+uzCllm;}function IxHUjxjD(rdORS) {var GUPXaBcr=LwfPkpZKrwFCYb" ascii
    $s19 = "x63\\x74\",\"\\x5a\\x52\\x63\\x53\\x5a\\x78\\x59\\x4d\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function jdKBrkd" ascii
    $s20 = "GUjIOasxDND*/dnYEKQFgqyuxh();var ylyIz = [LwfPkpZKrwFCYbDHhIFT[0], LwfPkpZKrwFCYbDHhIFT[1]];var DIlb=627-627;while(true) {if(DIl" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}