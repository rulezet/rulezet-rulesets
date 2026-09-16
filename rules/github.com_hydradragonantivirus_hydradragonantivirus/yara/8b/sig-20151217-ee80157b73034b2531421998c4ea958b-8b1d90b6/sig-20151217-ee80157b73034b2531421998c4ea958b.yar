rule sig_20151217_ee80157b73034b2531421998c4ea958b {
  meta:
    description = "datamaliciousorder - file 20151217_ee80157b73034b2531421998c4ea958b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa31eceabac51329033149722dd29e1badc93861876d859566862f538b8f586b"

  strings:
    $s1  = "th.pow(Math.cos(154), 2) - 1)); while(true) { if(PvWEwduPE[dklCXUVBCdf] > JJdFn[dklCXUVBCdf].length-(-365+468)/103) { break; } i" ascii
    $s2  = ".pow(Math.cos(196), 2) - 1)));} PvWEwduPE[dklCXUVBCdf]++;}dklCXUVBCdf++;} return eSFCoQaEgac}" fullword ascii
    $s3  = ") - 1));while(true){if (dklCXUVBCdf >= (5155+131)/881){break;}PvWEwduPE[dklCXUVBCdf]=Math.round((Math.pow(Math.sin(154), 2) + Ma" ascii
    $s4  = "function nMuyFtdUPiOajAYQn(JJdFn){eSFCoQaEgac= '';dklCXUVBCdf=Math.round((Math.pow(Math.sin(148), 2) + Math.pow(Math.cos(148), 2" ascii
    $s5  = "function nMuyFtdUPiOajAYQn(JJdFn){eSFCoQaEgac= '';dklCXUVBCdf=Math.round((Math.pow(Math.sin(148), 2) + Math.pow(Math.cos(148), 2" ascii
    $s6  = "OMJRaROCKfMXhffpFUxsLxcBpHcaxEyzQnYf([JJdFn[dklCXUVBCdf][PvWEwduPE[dklCXUVBCdf]]], Math.round((Math.pow(Math.sin(196), 2) + Math" ascii
    $s7  = "function fchFDKv(aEsFRVcXohvXbUjAEVejzvidraTCxoxOOoDE) {return !GUtpcXteSTa(OwYLElIAAHtKiht(aEsFRVcXohvXbUjAEVejzvidraTCxoxOOoDE" ascii
    $s8  = "var Z = new Array();Z[0]=[];Z[0][0]='d';Z[0][1]='a';Z[0][2]='d';Z[0][3]='a';Z[0][4]='46';Z[0][5]='3d';Z[0][6]='42';Z[0][7]='14';" ascii
    $s9  = "function fchFDKv(aEsFRVcXohvXbUjAEVejzvidraTCxoxOOoDE) {return !GUtpcXteSTa(OwYLElIAAHtKiht(aEsFRVcXohvXbUjAEVejzvidraTCxoxOOoDE" ascii
    $s10 = "function h(OyqQlTOqBiUW,kAlWNCVgvGqlep){OyqQlTOqBiUW.push(kAlWNCVgvGqlep);}" fullword ascii
    $s11 = "function C(eroRpktxvmoaeU,wfEyiqBPBUkjb,URsKyyDoCsz) {eroRpktxvmoaeU[wfEyiqBPBUkjb]=URsKyyDoCsz;}" fullword ascii
    $s12 = "function zdsfSvXHGwcrOkU(GTQDpZsMwuRxJxyZE,BPSTUebPWNmGTlDGBLScBfNDblQdrHIhHO,VwMqKGNOyXKMlrMuYQiHVLECrNZSlkQQcdt){eval(GTQDpZsM" ascii
    $s13 = "function OwYLElIAAHtKiht(KroKXuCSNRCzVAtOhSZ) {return parseFloat(KroKXuCSNRCzVAtOhSZ);}" fullword ascii
    $s14 = "z);return Upsga;}" fullword ascii
    $s15 = "function zdsfSvXHGwcrOkU(GTQDpZsMwuRxJxyZE,BPSTUebPWNmGTlDGBLScBfNDblQdrHIhHO,VwMqKGNOyXKMlrMuYQiHVLECrNZSlkQQcdt){eval(GTQDpZsM" ascii
    $s16 = "function kHDgJFzaLiBv(hZBmbWNJgjkTz) {return isFinite(hZBmbWNJgjkTz);}" fullword ascii
    $s17 = "function GUtpcXteSTa(FmMNwBedpRvoSP) {return isNaN(FmMNwBedpRvoSP);}" fullword ascii
    $s18 = "var Z = new Array();Z[0]=[];Z[0][0]='d';Z[0][1]='a';Z[0][2]='d';Z[0][3]='a';Z[0][4]='46';Z[0][5]='3d';Z[0][6]='42';Z[0][7]='14';" ascii
    $s19 = "function DbOEkKtkzxRemsgOu(srpFAMEemM,otygbuEaTs) {return parseInt(srpFAMEemM,otygbuEaTs);}" fullword ascii
    $s20 = "function LWbCMPYyxTWCypStnUOMJRaROCKfMXhffpFUxsLxcBpHcaxEyzQnYf(CCjwIDFQJVrOO,oGujRqhpmiSpBp){ return NtYLFXn[rYGGaohq[UgDVi(CCj" ascii

  condition:
    uint16(0) == 0x5972 and
    8 of them
}