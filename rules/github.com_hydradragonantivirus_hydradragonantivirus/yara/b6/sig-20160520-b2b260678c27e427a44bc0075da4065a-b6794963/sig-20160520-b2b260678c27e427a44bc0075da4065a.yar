rule sig_20160520_b2b260678c27e427a44bc0075da4065a {
  meta:
    description = "datamaliciousorder - file 20160520_b2b260678c27e427a44bc0075da4065a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2839278ac27c89b81b8b4fc3ba25240c74def67625c4d41b085465dc61d1366f"

  strings:
    $s1  = "function phSfhTRo(clivz) {var mdsvCnwq=vYAfwMtlXhrJaNiMg[2];for(var mZAiV=0;mZAiV<clivz;mZAiV++){WVuHr+=mdsvCnwq.charAt(Math.flo" ascii
    $s2  = "function phSfhTRo(clivz) {var mdsvCnwq=vYAfwMtlXhrJaNiMg[2];for(var mZAiV=0;mZAiV<clivz;mZAiV++){WVuHr+=mdsvCnwq.charAt(Math.flo" ascii
    $s3  = "function JenNj(shKmLTgr,oJRwF,pkZRVdYBoM){shKmLTgr.open();shKmLTgr.type = 1;shKmLTgr.write(oJRwF);shKmLTgr.position = 0;shKmLTgr" ascii
    $s4  = "C<TKlVEM.length;hAhFZIbC++) {MKgHgkK+=BesQH[TKlVEM[hAhFZIbC]];}return MKgHgkK.substring(3,MKgHgkK.length);}" fullword ascii
    $s5  = "function jYCOJ(pXDafGHy,TKlVEM,cKKSqHjGN){BesQH=pXDafGHy.split(cKKSqHjGN);MKgHgkK = vYAfwMtlXhrJaNiMg[13];for(hAhFZIbC=0;hAhFZIb" ascii
    $s6  = "function whsydK(jZdqvI){return jZdqvI.ExpandEnvironmentStrings(vYAfwMtlXhrJaNiMg[10])}" fullword ascii
    $s7  = "try{oHqZdGN=FyjSeLKWn(oXDkK[tziL], eHSIGWg() + vYAfwMtlXhrJaNiMg[9], 1)}catch(e){}; " fullword ascii
    $s8  = "function bksMu(jZdqvI){return new ActiveXObject(jZdqvI);}" fullword ascii
    $s9  = "function FyjSeLKWn(GDMxZODhx,glaREpQ,zITNnoCD){" fullword ascii
    $s10 = "function eHSIGWg() {var uuvF=100000;var FNCwBC = 100;return Math.random()*(uuvF-FNCwBC)+FNCwBC;}" fullword ascii
    $s11 = "or(Math.random()*mdsvCnwq.length));}return WVuHr;}" fullword ascii
    $s12 = "function jYCOJ(pXDafGHy,TKlVEM,cKKSqHjGN){BesQH=pXDafGHy.split(cKKSqHjGN);MKgHgkK = vYAfwMtlXhrJaNiMg[13];for(hAhFZIbC=0;hAhFZIb" ascii
    $s13 = "function JenNj(shKmLTgr,oJRwF,pkZRVdYBoM){shKmLTgr.open();shKmLTgr.type = 1;shKmLTgr.write(oJRwF);shKmLTgr.position = 0;shKmLTgr" ascii
    $s14 = "if (oHqZdGN==0) break;" fullword ascii
    $s15 = "CANV, false);vNjxUlt.send();}" fullword ascii
    $s16 = "function TPDg(HlCANV,vNjxUlt){VjMq = vYAfwMtlXhrJaNiMg[11].split(vYAfwMtlXhrJaNiMg[12]);vNjxUlt.open(VjMq[0]+VjMq[2]+VjMq[3], Hl" ascii
    $s17 = "function TPDg(HlCANV,vNjxUlt){VjMq = vYAfwMtlXhrJaNiMg[11].split(vYAfwMtlXhrJaNiMg[12]);vNjxUlt.open(VjMq[0]+VjMq[2]+VjMq[3], Hl" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}