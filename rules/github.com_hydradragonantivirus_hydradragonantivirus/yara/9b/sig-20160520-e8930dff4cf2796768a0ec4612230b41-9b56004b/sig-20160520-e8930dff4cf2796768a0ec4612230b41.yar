rule sig_20160520_e8930dff4cf2796768a0ec4612230b41 {
  meta:
    description = "datamaliciousorder - file 20160520_e8930dff4cf2796768a0ec4612230b41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6abfacc1d834b8600bea7032046a6d078d3a5787aa6f49e9fe08caae43d3ca4e"

  strings:
    $s1  = "function EMceuGQX(pIvbf) {var QvbkDWhv=wIXtJqPNW[2];for(var UChdl=0;UChdl<pIvbf;UChdl++){skcDW+=QvbkDWhv.charAt(Math.floor(Math." ascii
    $s2  = "function EMceuGQX(pIvbf) {var QvbkDWhv=wIXtJqPNW[2];for(var UChdl=0;UChdl<pIvbf;UChdl++){skcDW+=QvbkDWhv.charAt(Math.floor(Math." ascii
    $s3  = "function GpArP(cIddYGbn,aaULGU,UqQTNsbdK){ickHy=cIddYGbn.split(UqQTNsbdK);deeyYhj = wIXtJqPNW[13];for(KmbwJWTj=0;KmbwJWTj<aaULGU" ascii
    $s4  = "function eUtSnL(roEeVz){return roEeVz.ExpandEnvironmentStrings(wIXtJqPNW[10])}" fullword ascii
    $s5  = "function GpArP(cIddYGbn,aaULGU,UqQTNsbdK){ickHy=cIddYGbn.split(UqQTNsbdK);deeyYhj = wIXtJqPNW[13];for(KmbwJWTj=0;KmbwJWTj<aaULGU" ascii
    $s6  = "function FQTMMMR() {var jZsd=100000;var dEBCZk = 100;return Math.random()*(jZsd-dEBCZk)+dEBCZk;}" fullword ascii
    $s7  = "function isxnP(pyFIUokK,KCtuQ,BYKSVsgUXr){pyFIUokK.open();pyFIUokK.type = 1;pyFIUokK.write(KCtuQ);pyFIUokK.position = 0;pyFIUokK" ascii
    $s8  = "function WNGsBKNTe(qOCqXhzwx,QohinZK,WynPfTiH){" fullword ascii
    $s9  = "try{WNGsBKNTe(qRoMI[Tvzm], FQTMMMR() + wIXtJqPNW[9], 1)}catch(e){}; " fullword ascii
    $s10 = "random()*QvbkDWhv.length));}return skcDW;}" fullword ascii
    $s11 = ".length;KmbwJWTj++) {deeyYhj+=ickHy[aaULGU[KmbwJWTj]];}return deeyYhj.substring(3,deeyYhj.length);}" fullword ascii
    $s12 = "function IHHcY(roEeVz){return new ActiveXObject(roEeVz);}" fullword ascii
    $s13 = "function isxnP(pyFIUokK,KCtuQ,BYKSVsgUXr){pyFIUokK.open();pyFIUokK.type = 1;pyFIUokK.write(KCtuQ);pyFIUokK.position = 0;pyFIUokK" ascii
    $s14 = "function ECso(ETqbeA,EWCAsQW){ztbM = wIXtJqPNW[11].split(wIXtJqPNW[12]);EWCAsQW.open(ztbM[0]+ztbM[2]+ztbM[3], ETqbeA, false);EWC" ascii
    $s15 = "function ECso(ETqbeA,EWCAsQW){ztbM = wIXtJqPNW[11].split(wIXtJqPNW[12]);EWCAsQW.open(ztbM[0]+ztbM[2]+ztbM[3], ETqbeA, false);EWC" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}