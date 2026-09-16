rule sig_20151217_468937e0eb5129ce53ef6c12dc85a6ea {
  meta:
    description = "datamaliciousorder - file 20151217_468937e0eb5129ce53ef6c12dc85a6ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "690f89490fc8e4d26f91c0ab8d7bbccae809e0f83a374a3afb07982306a34111"

  strings:
    $s1  = "th.pow(Math.cos(270), 2) - 1)); while(true) { if(lpGmfbnCb[AmHwZtztTYR] > rCLIU[AmHwZtztTYR].length-(-182+555)/373) { break; } i" ascii
    $s2  = "function twXRAQqfkiuQWAdis(rCLIU){LQoxodhieSE= '';AmHwZtztTYR=Math.round((Math.pow(Math.sin(609), 2) + Math.pow(Math.cos(609), 2" ascii
    $s3  = ") - 1));while(true){if (AmHwZtztTYR >= (3396+102)/583){break;}lpGmfbnCb[AmHwZtztTYR]=Math.round((Math.pow(Math.sin(270), 2) + Ma" ascii
    $s4  = "ow(Math.cos(132), 2) - 1)));} lpGmfbnCb[AmHwZtztTYR]++;}AmHwZtztTYR++;} return LQoxodhieSE}" fullword ascii
    $s5  = "function twXRAQqfkiuQWAdis(rCLIU){LQoxodhieSE= '';AmHwZtztTYR=Math.round((Math.pow(Math.sin(609), 2) + Math.pow(Math.cos(609), 2" ascii
    $s6  = "function YnfdmFD(ClHcDsuZkwIxaIxPrTFqMtyjaBFFGyUceOzO) {return !lIiRzSypSYH(tCEYjGRuMcNoywD(ClHcDsuZkwIxaIxPrTFqMtyjaBFFGyUceOzO" ascii
    $s7  = "var t = new Array();t[0]=[];t[0][0]='d';t[0][1]='a';t[0][2]='d';t[0][3]='a';t[0][4]='46';t[0][5]='3d';t[0][6]='42';t[0][7]='14';" ascii
    $s8  = "function ovKeHDdZyGjlqOMtDPhKUOJTAWfRIgdgylzXjJRdSJtNqzaiPpxtmd(hFimqkAqmGLkA,xlMFqCPrhjwFzy){ return zwXXeuN[fOSHYSAA[fbouN(hFi" ascii
    $s9  = "function tCEYjGRuMcNoywD(yEZoqWVVCXQhVWeFIWH) {return parseFloat(yEZoqWVVCXQhVWeFIWH);}" fullword ascii
    $s10 = "function HgFZRaSoaeMypOLif(hKKJEfosep,PGKmKkxWkI) {return parseInt(hKKJEfosep,PGKmKkxWkI);}" fullword ascii
    $s11 = "function ByqfTtGOagDdbBD(PgrgNCoNhcOODfsdt,gHrEkOpVtndPKFhazkVLWckRMSrwgvIxnA,xiSOKMFeapSRLPbXuovuNQEBIgLWqVsDinF){eval(PgrgNCoN" ascii
    $s12 = "function lIiRzSypSYH(EJuTgFwdMXfqJI) {return isNaN(EJuTgFwdMXfqJI);}" fullword ascii
    $s13 = "function fbouN(DhWAZDfDFhp,jmcOjXvGWznMz,yiOHeTgn){waud=HgFZRaSoaeMypOLif(DhWAZDfDFhp,jmcOjXvGWznMz);NUnTi=waud.toString(yiOHeTg" ascii
    $s14 = "function fbouN(DhWAZDfDFhp,jmcOjXvGWznMz,yiOHeTgn){waud=HgFZRaSoaeMypOLif(DhWAZDfDFhp,jmcOjXvGWznMz);NUnTi=waud.toString(yiOHeTg" ascii
    $s15 = "function ByqfTtGOagDdbBD(PgrgNCoNhcOODfsdt,gHrEkOpVtndPKFhazkVLWckRMSrwgvIxnA,xiSOKMFeapSRLPbXuovuNQEBIgLWqVsDinF){eval(PgrgNCoN" ascii
    $s16 = "n);return NUnTi;}" fullword ascii
    $s17 = "function D(yUPmFSbKawDEuQ,hLQUyUMtkNJRn,qvKsSEegExv) {yUPmFSbKawDEuQ[hLQUyUMtkNJRn]=qvKsSEegExv;}" fullword ascii
    $s18 = "function W(UqKHKOiZdqHT,QMHvLgiNpTXeFL){UqKHKOiZdqHT.push(QMHvLgiNpTXeFL);}" fullword ascii
    $s19 = "function ovKeHDdZyGjlqOMtDPhKUOJTAWfRIgdgylzXjJRdSJtNqzaiPpxtmd(hFimqkAqmGLkA,xlMFqCPrhjwFzy){ return zwXXeuN[fOSHYSAA[fbouN(hFi" ascii
    $s20 = "function pgrPlDszIzGN(foHnFLQLwewWG) {return isFinite(foHnFLQLwewWG);}" fullword ascii

  condition:
    uint16(0) == 0x4f66 and
    8 of them
}