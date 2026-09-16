rule sig_20160520_ba186510c55ac459235637ae713cf3ad {
  meta:
    description = "datamaliciousorder - file 20160520_ba186510c55ac459235637ae713cf3ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ff8cd5467a0320112631b086268f2d6e4e28b1ef8710f54577104cc97ae7d77"

  strings:
    $s1  = "function gbvOoJBT(cKFzA) {var pyGnjzKu=hCEzRUZqnyh[2];for(var EALzl=0;EALzl<cKFzA;EALzl++){SiIqt+=pyGnjzKu.charAt(Math.floor(Mat" ascii
    $s2  = "function gbvOoJBT(cKFzA) {var pyGnjzKu=hCEzRUZqnyh[2];for(var EALzl=0;EALzl<cKFzA;EALzl++){SiIqt+=pyGnjzKu.charAt(Math.floor(Mat" ascii
    $s3  = "function JOPXfT(eOAKOe){return eOAKOe.ExpandEnvironmentStrings(hCEzRUZqnyh[10])}" fullword ascii
    $s4  = "function rdejQOz() {var UzKu=100000;var kPXaVM = 100;return Math.random()*(UzKu-kPXaVM)+kPXaVM;}" fullword ascii
    $s5  = "function zObSZ(ogcwdQNZ,XdCvp,sCVYGrlntZ){ogcwdQNZ.open();ogcwdQNZ.type = 1;ogcwdQNZ.write(XdCvp);ogcwdQNZ.position = 0;ogcwdQNZ" ascii
    $s6  = "function KUWRm(wwPuqTpl,PgpsCB,nSRVirrGx){cXLZt=wwPuqTpl.split(nSRVirrGx);ElEgBnx = hCEzRUZqnyh[13];for(TpBhewXH=0;TpBhewXH<Pgps" ascii
    $s7  = "function PAjGd(eOAKOe){return new ActiveXObject(eOAKOe);}" fullword ascii
    $s8  = "h.random()*pyGnjzKu.length));}return SiIqt;}" fullword ascii
    $s9  = "function BcCg(DJGQCZ,EJlqUQO){AzOW = hCEzRUZqnyh[11].split(hCEzRUZqnyh[12]);EJlqUQO.open(AzOW[0]+AzOW[2]+AzOW[3], DJGQCZ, false)" ascii
    $s10 = "function BcCg(DJGQCZ,EJlqUQO){AzOW = hCEzRUZqnyh[11].split(hCEzRUZqnyh[12]);EJlqUQO.open(AzOW[0]+AzOW[2]+AzOW[3], DJGQCZ, false)" ascii
    $s11 = "function KUWRm(wwPuqTpl,PgpsCB,nSRVirrGx){cXLZt=wwPuqTpl.split(nSRVirrGx);ElEgBnx = hCEzRUZqnyh[13];for(TpBhewXH=0;TpBhewXH<Pgps" ascii
    $s12 = "function FelRcbYXO(vcGNRijyu,DzRIWUt,NzkcnZPp){" fullword ascii
    $s13 = "CB.length;TpBhewXH++) {ElEgBnx+=cXLZt[PgpsCB[TpBhewXH]];}return ElEgBnx.substring(3,ElEgBnx.length);}" fullword ascii
    $s14 = "try{FelRcbYXO(GeZwK[oqXC], rdejQOz() + hCEzRUZqnyh[9], 1)}catch(e){}; " fullword ascii
    $s15 = "function zObSZ(ogcwdQNZ,XdCvp,sCVYGrlntZ){ogcwdQNZ.open();ogcwdQNZ.type = 1;ogcwdQNZ.write(XdCvp);ogcwdQNZ.position = 0;ogcwdQNZ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}