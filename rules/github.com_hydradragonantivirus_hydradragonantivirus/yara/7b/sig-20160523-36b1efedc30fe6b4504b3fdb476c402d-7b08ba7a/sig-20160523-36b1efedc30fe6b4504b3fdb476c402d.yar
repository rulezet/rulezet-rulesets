rule sig_20160523_36b1efedc30fe6b4504b3fdb476c402d {
  meta:
    description = "datamaliciousorder - file 20160523_36b1efedc30fe6b4504b3fdb476c402d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "027b27713df271c7c9fad2cb913f8000574e9edf50cc9b642b27e3cbbbcb3f44"

  strings:
    $s1  = "function XxsCFasYfy(XrpPJtzy,JpDxBRRlqjiM) {XrpPJtzy.Run(JpDxBRRlqjiM, 0x1, 0x0);}" fullword ascii
    $s2  = "function PmxRZprH(TdkCV) {var IosdIoxQ=NqzdqyDbomLMDLcipk[13];for(var juIhP=0;juIhP<TdkCV;juIhP++){uqyFx+=IosdIoxQ.charAt(Math.f" ascii
    $s3  = "function PmxRZprH(TdkCV) {var IosdIoxQ=NqzdqyDbomLMDLcipk[13];for(var juIhP=0;juIhP<TdkCV;juIhP++){uqyFx+=IosdIoxQ.charAt(Math.f" ascii
    $s4  = "function AYvLCI(iMrhGf){return iMrhGf.ExpandEnvironmentStrings(NqzdqyDbomLMDLcipk[9])}" fullword ascii
    $s5  = "function cCLSV(hBxXXPGH,dOlXf,iFthkERPFB){FvtJ(hBxXXPGH);ApjopcUF(hBxXXPGH);mZQfipa(hBxXXPGH,dOlXf);huenNOHsl(hBxXXPGH);zkMB(hBx" ascii
    $s6  = "function huenNOHsl(WFRyxJ) {var abudMQtAtq=[];WFRyxJ.position=abudMQtAtq.length*(5504443-995);}" fullword ascii
    $s7  = "rNRjPN, false);FdjMGoZ.send();}" fullword ascii
    $s8  = "function RgDo(rNRjPN,FdjMGoZ){OeJi = NqzdqyDbomLMDLcipk[10].split(NqzdqyDbomLMDLcipk[11]);FdjMGoZ.open(OeJi[0]+OeJi[2]+OeJi[3], " ascii
    $s9  = "function FvtJ(Thhiss) {Thhiss.open();}" fullword ascii
    $s10 = "function bKqXxRu(){return Math.random();}" fullword ascii
    $s11 = "function cpVqq(lToAnnhY,ThhDdg,aFoqXXzoJ){LqrrL=lToAnnhY.split(aFoqXXzoJ);luwLxKw = NqzdqyDbomLMDLcipk[12];for(WjgwvpxU=0;Wjgwvp" ascii
    $s12 = "if(VUUp>AAJDe.length) break;" fullword ascii
    $s13 = "function ApjopcUF(SUGEbPYVi) {SUGEbPYVi.type=1;}" fullword ascii
    $s14 = "function cpVqq(lToAnnhY,ThhDdg,aFoqXXzoJ){LqrrL=lToAnnhY.split(aFoqXXzoJ);luwLxKw = NqzdqyDbomLMDLcipk[12];for(WjgwvpxU=0;Wjgwvp" ascii
    $s15 = "function zkMB(qUkTYNE,rcDmvGA) {qUkTYNE.saveToFile(rcDmvGA, 2);}" fullword ascii
    $s16 = "function cCLSV(hBxXXPGH,dOlXf,iFthkERPFB){FvtJ(hBxXXPGH);ApjopcUF(hBxXXPGH);mZQfipa(hBxXXPGH,dOlXf);huenNOHsl(hBxXXPGH);zkMB(hBx" ascii
    $s17 = "function abpqmJi(jNrQS) {jNrQS.close();}" fullword ascii
    $s18 = "function lEBRr(iMrhGf){return new ActiveXObject(iMrhGf);}" fullword ascii
    $s19 = "function BZVSdgZ() {var ZZew=100000;var mFqqRO = 100;return bKqXxRu()*(ZZew-mFqqRO)+mFqqRO;}" fullword ascii
    $s20 = "function mZQfipa(jdZM,nVIJI) {jdZM.write(nVIJI);}" fullword ascii

  condition:
    uint16(0) == 0x1327 and
    8 of them
}