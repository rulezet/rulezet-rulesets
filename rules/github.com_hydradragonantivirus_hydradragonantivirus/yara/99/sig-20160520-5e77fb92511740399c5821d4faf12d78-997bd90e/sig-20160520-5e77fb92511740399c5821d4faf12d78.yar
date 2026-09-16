rule sig_20160520_5e77fb92511740399c5821d4faf12d78 {
  meta:
    description = "datamaliciousorder - file 20160520_5e77fb92511740399c5821d4faf12d78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "599b0e7ea0c9645b3d402835b2098bea1b4bb15d6197f21fe06ec25ef7902b22"

  strings:
    $s1  = "function FAfZvUxu(DfhUw) {var EoLSqxEi=aZhGwov[2];for(var NMLlU=0;NMLlU<DfhUw;NMLlU++){OStjG+=EoLSqxEi.charAt(Math.floor(Math.ra" ascii
    $s2  = "function FAfZvUxu(DfhUw) {var EoLSqxEi=aZhGwov[2];for(var NMLlU=0;NMLlU<DfhUw;NMLlU++){OStjG+=EoLSqxEi.charAt(Math.floor(Math.ra" ascii
    $s3  = "function AJIRc(gfiJgI){return new ActiveXObject(gfiJgI);}" fullword ascii
    $s4  = "function Fmziw(JllhpHpj,iXmCU,SuJDEEDNTj){JllhpHpj.open();JllhpHpj.type = 1;JllhpHpj.write(iXmCU);JllhpHpj.position = 0;JllhpHpj" ascii
    $s5  = "function rPhvEk(gfiJgI){return gfiJgI.ExpandEnvironmentStrings(aZhGwov[10])}" fullword ascii
    $s6  = "function YKiTFza() {var NNmO=100000;var FhrXBZ = 100;return Math.random()*(NNmO-FhrXBZ)+FhrXBZ;}" fullword ascii
    $s7  = "function NJKSW(XvgybyAK,uZkAZB,XkqkYGqFY){pHEBh=XvgybyAK.split(XkqkYGqFY);eRHwCnR = aZhGwov[13];for(hzRiENxo=0;hzRiENxo<uZkAZB.l" ascii
    $s8  = "ndom()*EoLSqxEi.length));}return OStjG;}" fullword ascii
    $s9  = "ength;hzRiENxo++) {eRHwCnR+=pHEBh[uZkAZB[hzRiENxo]];}return eRHwCnR.substring(3,eRHwCnR.length);}" fullword ascii
    $s10 = "function NJKSW(XvgybyAK,uZkAZB,XkqkYGqFY){pHEBh=XvgybyAK.split(XkqkYGqFY);eRHwCnR = aZhGwov[13];for(hzRiENxo=0;hzRiENxo<uZkAZB.l" ascii
    $s11 = "function JEVb(YHwxVb,IpyqqWg){FFiS = aZhGwov[11].split(aZhGwov[12]);IpyqqWg.open(FFiS[0]+FFiS[2]+FFiS[3], YHwxVb, false);IpyqqWg" ascii
    $s12 = "function JEVb(YHwxVb,IpyqqWg){FFiS = aZhGwov[11].split(aZhGwov[12]);IpyqqWg.open(FFiS[0]+FFiS[2]+FFiS[3], YHwxVb, false);IpyqqWg" ascii
    $s13 = "function Fmziw(JllhpHpj,iXmCU,SuJDEEDNTj){JllhpHpj.open();JllhpHpj.type = 1;JllhpHpj.write(iXmCU);JllhpHpj.position = 0;JllhpHpj" ascii
    $s14 = "try{vOEHPmhzb(iGept[nRLI], YKiTFza() + aZhGwov[9], 1)}catch(e){}; " fullword ascii
    $s15 = "function vOEHPmhzb(iMCrtruxm,ugDETqw,OoemHCaK){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}