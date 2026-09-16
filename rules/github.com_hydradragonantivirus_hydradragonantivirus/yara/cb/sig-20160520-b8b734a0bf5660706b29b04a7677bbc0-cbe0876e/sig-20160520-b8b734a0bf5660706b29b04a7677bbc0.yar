rule sig_20160520_b8b734a0bf5660706b29b04a7677bbc0 {
  meta:
    description = "datamaliciousorder - file 20160520_b8b734a0bf5660706b29b04a7677bbc0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f79d8507dd65b547579dd318d3ef9925de96f1c570c37a2472b25eaabc199cd"

  strings:
    $s1  = "function IOvclddJ(TssVF) {var mZfSRkfE=NEIMLMadQ[2];for(var KLnpY=0;KLnpY<TssVF;KLnpY++){NuXja+=mZfSRkfE.charAt(Math.floor(Math." ascii
    $s2  = "function IOvclddJ(TssVF) {var mZfSRkfE=NEIMLMadQ[2];for(var KLnpY=0;KLnpY<TssVF;KLnpY++){NuXja+=mZfSRkfE.charAt(Math.floor(Math." ascii
    $s3  = "function kWqeQ(BEFtHCKN,oPeoSw,ZPtbgGqKL){fKDTL=BEFtHCKN.split(ZPtbgGqKL);WxxUvtd = NEIMLMadQ[13];for(IFbykNgG=0;IFbykNgG<oPeoSw" ascii
    $s4  = ".length;IFbykNgG++) {WxxUvtd+=fKDTL[oPeoSw[IFbykNgG]];}return WxxUvtd.substring(3,WxxUvtd.length);}" fullword ascii
    $s5  = "function OQsJ(zHYgdH,nDZTwUl){Ylvm = NEIMLMadQ[11].split(NEIMLMadQ[12]);nDZTwUl.open(Ylvm[0]+Ylvm[2]+Ylvm[3], zHYgdH, false);nDZ" ascii
    $s6  = "function wLhMi(mUdEbe){return new ActiveXObject(mUdEbe);}" fullword ascii
    $s7  = "function hwqrrqA() {var GWwr=100000;var IOLujk = 100;return Math.random()*(GWwr-IOLujk)+IOLujk;}" fullword ascii
    $s8  = "function AwxFJKiTl(nMoKXdXLt,dsLUmEV,rAkbcuro){" fullword ascii
    $s9  = "function OQsJ(zHYgdH,nDZTwUl){Ylvm = NEIMLMadQ[11].split(NEIMLMadQ[12]);nDZTwUl.open(Ylvm[0]+Ylvm[2]+Ylvm[3], zHYgdH, false);nDZ" ascii
    $s10 = "function UJvvF(ayqVQIrP,NKQKT,REFONbYDJW){ayqVQIrP.open();ayqVQIrP.type = 1;ayqVQIrP.write(NKQKT);ayqVQIrP.position = 0;ayqVQIrP" ascii
    $s11 = "if (OlnxhMX==0) break;" fullword ascii
    $s12 = "random()*mZfSRkfE.length));}return NuXja;}" fullword ascii
    $s13 = "function UJvvF(ayqVQIrP,NKQKT,REFONbYDJW){ayqVQIrP.open();ayqVQIrP.type = 1;ayqVQIrP.write(NKQKT);ayqVQIrP.position = 0;ayqVQIrP" ascii
    $s14 = "try{OlnxhMX=AwxFJKiTl(KZpHF[ebMC], hwqrrqA() + NEIMLMadQ[9], 1)}catch(e){}; " fullword ascii
    $s15 = "function kWqeQ(BEFtHCKN,oPeoSw,ZPtbgGqKL){fKDTL=BEFtHCKN.split(ZPtbgGqKL);WxxUvtd = NEIMLMadQ[13];for(IFbykNgG=0;IFbykNgG<oPeoSw" ascii
    $s16 = "function KDequx(mUdEbe){return mUdEbe.ExpandEnvironmentStrings(NEIMLMadQ[10])}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}