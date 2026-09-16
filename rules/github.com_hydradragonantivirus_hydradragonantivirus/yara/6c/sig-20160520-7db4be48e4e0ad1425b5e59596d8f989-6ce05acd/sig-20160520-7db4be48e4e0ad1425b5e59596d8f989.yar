rule sig_20160520_7db4be48e4e0ad1425b5e59596d8f989 {
  meta:
    description = "datamaliciousorder - file 20160520_7db4be48e4e0ad1425b5e59596d8f989.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bc8b28eb7fc4054212f7a86d61912e13407dae19a27246a79204cf8664dff2e"

  strings:
    $s1  = "function TkjBrjXB(USZZO) {var eoyLlpeV=yFTgXWjCWYVfJtvJaITNgqxz[2];for(var eZvfc=0;eZvfc<USZZO;eZvfc++){RDzWQ+=eoyLlpeV.charAt(M" ascii
    $s2  = "function TkjBrjXB(USZZO) {var eoyLlpeV=yFTgXWjCWYVfJtvJaITNgqxz[2];for(var eZvfc=0;eZvfc<USZZO;eZvfc++){RDzWQ+=eoyLlpeV.charAt(M" ascii
    $s3  = "ath.floor(Math.random()*eoyLlpeV.length));}return RDzWQ;}" fullword ascii
    $s4  = "function Kjuikt(iWHxnP){return iWHxnP.ExpandEnvironmentStrings(yFTgXWjCWYVfJtvJaITNgqxz[10])}" fullword ascii
    $s5  = "function TAgPK(oMYCemSC,izvnlQ,hOyeZLIFw){yuNzZ=oMYCemSC.split(hOyeZLIFw);xQYvAsV = yFTgXWjCWYVfJtvJaITNgqxz[13];for(jYnwLhsx=0;" ascii
    $s6  = "function DRLcF(iWHxnP){return new ActiveXObject(iWHxnP);}" fullword ascii
    $s7  = "function TAgPK(oMYCemSC,izvnlQ,hOyeZLIFw){yuNzZ=oMYCemSC.split(hOyeZLIFw);xQYvAsV = yFTgXWjCWYVfJtvJaITNgqxz[13];for(jYnwLhsx=0;" ascii
    $s8  = "function BfynT(SupSQenH,RCOZm,kWfUdpJgDZ){SupSQenH.open();SupSQenH.type = 1;SupSQenH.write(RCOZm);SupSQenH.position = 0;SupSQenH" ascii
    $s9  = "jYnwLhsx<izvnlQ.length;jYnwLhsx++) {xQYvAsV+=yuNzZ[izvnlQ[jYnwLhsx]];}return xQYvAsV.substring(3,xQYvAsV.length);}" fullword ascii
    $s10 = "function ZPKE(JlVjco,kuMoapb){fqyF = yFTgXWjCWYVfJtvJaITNgqxz[11].split(yFTgXWjCWYVfJtvJaITNgqxz[12]);kuMoapb.open(fqyF[0]+fqyF[" ascii
    $s11 = "function BfynT(SupSQenH,RCOZm,kWfUdpJgDZ){SupSQenH.open();SupSQenH.type = 1;SupSQenH.write(RCOZm);SupSQenH.position = 0;SupSQenH" ascii
    $s12 = "function ZPKE(JlVjco,kuMoapb){fqyF = yFTgXWjCWYVfJtvJaITNgqxz[11].split(yFTgXWjCWYVfJtvJaITNgqxz[12]);kuMoapb.open(fqyF[0]+fqyF[" ascii
    $s13 = "function umbbExF() {var tMUA=100000;var fZPFlT = 100;return Math.random()*(tMUA-fZPFlT)+fZPFlT;}" fullword ascii
    $s14 = "if (VfPVeOw==0) break;" fullword ascii
    $s15 = "function lmsAuBeIN(XnXyxjXwB,cHoOErx,oaUWGcJk){" fullword ascii
    $s16 = "try{VfPVeOw=lmsAuBeIN(kEBxH[KFPy], umbbExF() + yFTgXWjCWYVfJtvJaITNgqxz[9], 1)}catch(e){}; " fullword ascii
    $s17 = "2]+fqyF[3], JlVjco, false);kuMoapb.send();}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}