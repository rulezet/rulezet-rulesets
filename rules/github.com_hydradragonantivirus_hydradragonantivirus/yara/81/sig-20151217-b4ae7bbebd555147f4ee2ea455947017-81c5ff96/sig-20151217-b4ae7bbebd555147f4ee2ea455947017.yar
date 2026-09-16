rule sig_20151217_b4ae7bbebd555147f4ee2ea455947017 {
  meta:
    description = "datamaliciousorder - file 20151217_b4ae7bbebd555147f4ee2ea455947017.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cf269ebd73daf0cbb736c4397f62d9f933b9fa81ffa146e0f683d2167f18700"

  strings:
    $s1  = "function QSMfupFlnvepYSeVs(NxYFg){NhgFkjzpuwx= '';SNcfJUSPZQo=Math.round((Math.pow(Math.sin(850), 2) + Math.pow(Math.cos(850), 2" ascii
    $s2  = "w(Math.cos(600), 2) - 1)));} PfKRjNWRI[SNcfJUSPZQo]++;}SNcfJUSPZQo++;} return NhgFkjzpuwx}" fullword ascii
    $s3  = "h.pow(Math.cos(378), 2) - 1)); while(true) { if(PfKRjNWRI[SNcfJUSPZQo] > NxYFg[SNcfJUSPZQo].length-(548+318)/866) { break; } if " ascii
    $s4  = ") - 1));while(true){if (SNcfJUSPZQo >= (5409+75)/914){break;}PfKRjNWRI[SNcfJUSPZQo]=Math.round((Math.pow(Math.sin(378), 2) + Mat" ascii
    $s5  = "function QSMfupFlnvepYSeVs(NxYFg){NhgFkjzpuwx= '';SNcfJUSPZQo=Math.round((Math.pow(Math.sin(850), 2) + Math.pow(Math.cos(850), 2" ascii
    $s6  = "function oewuflj(ZFSfrKMnwqXFTeZyKuVsiXlHIyIDPlrYbBCV) {return !FnopFzemrXT(jGlxwTaLazEYaDQ(ZFSfrKMnwqXFTeZyKuVsiXlHIyIDPlrYbBCV" ascii
    $s7  = "function CoheOvDfKMcKXmtKGcIzIefSOkuURTUYcDKtEbuoAoOyjRtvPiTVdT(DbicnDmFqGvrE,svfDOTrYMYLSmS){ return kZHohoP[KvqSkkrn[aejhG(Dbi" ascii
    $s8  = "function CoheOvDfKMcKXmtKGcIzIefSOkuURTUYcDKtEbuoAoOyjRtvPiTVdT(DbicnDmFqGvrE,svfDOTrYMYLSmS){ return kZHohoP[KvqSkkrn[aejhG(Dbi" ascii
    $s9  = "var b = new Array();b[0]=[];b[0][0]='d';b[0][1]='a';b[0][2]='d';b[0][3]='a';b[0][4]='46';b[0][5]='3d';b[0][6]='42';b[0][7]='14';" ascii
    $s10 = "function DNmpLeuaZcDyIqa(MPGKjIlobZFtwHnKC,CmyBPfYahlZRBXSfNIecUBQhuuTjNgJlqM,xDuquXzypSvJQGSEVLEASJeFcOLDgMHvqom){eval(MPGKjIlo" ascii
    $s11 = "Q);return hSNSx;}" fullword ascii
    $s12 = "function aejhG(xzgZXiKPJls,WurQovgrBlJXp,fcZvJTLQ){iTCI=CgSboIhagtNAFpBbn(xzgZXiKPJls,WurQovgrBlJXp);hSNSx=iTCI.toString(fcZvJTL" ascii
    $s13 = "function FnopFzemrXT(WxupyntGsNHNGG) {return isNaN(WxupyntGsNHNGG);}" fullword ascii
    $s14 = "function aejhG(xzgZXiKPJls,WurQovgrBlJXp,fcZvJTLQ){iTCI=CgSboIhagtNAFpBbn(xzgZXiKPJls,WurQovgrBlJXp);hSNSx=iTCI.toString(fcZvJTL" ascii
    $s15 = "function oewuflj(ZFSfrKMnwqXFTeZyKuVsiXlHIyIDPlrYbBCV) {return !FnopFzemrXT(jGlxwTaLazEYaDQ(ZFSfrKMnwqXFTeZyKuVsiXlHIyIDPlrYbBCV" ascii
    $s16 = "var b = new Array();b[0]=[];b[0][0]='d';b[0][1]='a';b[0][2]='d';b[0][3]='a';b[0][4]='46';b[0][5]='3d';b[0][6]='42';b[0][7]='14';" ascii
    $s17 = "function jGlxwTaLazEYaDQ(yAlEsTIiShOaoDEJUpz) {return parseFloat(yAlEsTIiShOaoDEJUpz);}" fullword ascii
    $s18 = "function z(IeRzGLqxsNjU,tRyciKMIECyagm){IeRzGLqxsNjU.push(tRyciKMIECyagm);}" fullword ascii
    $s19 = "function p(AmHUSxMQajsZva,AixRZbbkbMzyF,aEzzqFmwFep) {AmHUSxMQajsZva[AixRZbbkbMzyF]=aEzzqFmwFep;}" fullword ascii
    $s20 = "function CgSboIhagtNAFpBbn(NBWZBtakCd,zwcTgeNYtm) {return parseInt(NBWZBtakCd,zwcTgeNYtm);}" fullword ascii

  condition:
    uint16(0) == 0x764b and
    8 of them
}