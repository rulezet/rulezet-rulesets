rule sig_20151008_6f10b2c11581e8ba50c495ffa5349932 {
  meta:
    description = "datamaliciousorder - file 20151008_6f10b2c11581e8ba50c495ffa5349932.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50ce725cee0947d7541bb67c0194557c18947903d3936e66c30dc087e9ed5cae"

  strings:
    $s1  = "var str=\"5551575E0D0A020B24011C1405101001070C4A070B095E225E0D0A1001160B090103054A070B094A10165E17011614565E5550505057555452555D" ascii
    $s2  = " function ydba() { rrk += ')+Str'; }; function avd() { rrk += 'from'; }; function ixhe() { rrk += '.com'; }; function eucm() { r" ascii
    $s3  = "y() { rrk += '); i'; }; function qzn() { rrk += 'ipt.C'; }; function swd() { rrk += 'atec'; }; function upg() { rrk += 'eyesl'; " ascii
    $s4  = "h() { rrk += 'l.'; }; function hfm() { rrk += 'b = '; }; function pmko() { rrk += '.Crea'; }; function czz() { rrk += 'GET'; }; " ascii
    $s5  = " rsw() { rrk += '.She'; }; function wcic() { rrk += 'xo'; }; function smv() { rrk += 'xo.on'; }; function bxg() { rrk += 'B.'; }" ascii
    $s6  = "function hps() { rrk += 'ry '; }; function qza() { rrk += '.Cre'; }; function mysd() { rrk += '{ '; }; function sonf() { rrk += " ascii
    $s7  = "nction vqgq() { rrk += '/co'; }; function fbp() { rrk += 'h.ran'; }; function rmt() { rrk += '(); }'; }; function lmyt() { rrk +" ascii
    $s8  = "= 'e = 1'; }; function lpe() { rrk += 'com '; }; function ilu() { rrk += 'r x'; }; function efof() { rrk += '; f'; }; var rrk = " ascii
    $s9  = "k += 'ect(\"'; }; function wqge() { rrk += ' 0; '; }; function jyvq() { rrk += '+\"'; }; function crgd() { rrk += ' && '; }; fun" ascii
    $s10 = "on kwvu() { rrk += 'ings('; }; function zff() { rrk += 'dyst'; }; function qlkp() { rrk += 'LHTT'; }; function zewb() { rrk += '" ascii
    $s11 = "xgo() { rrk += 'o '; }; function oft() { rrk += '1) b'; }; function luu() { rrk += 'lar'; }; function cme() { rrk += ' i<b.'; };" ascii
    $s12 = "+= 'ite(x'; }; function cvxk() { rrk += '+\".'; }; function xfu() { rrk += '1); d'; }; function lrnr() { rrk += 'y.'; }; functio" ascii
    $s13 = "rk += 'r) {'; }; function hfiw() { ypo(rrk); };  function szxx() { rrk += 'fn,2)'; }; function xeds() { rrk += '.spli'; }; funct" ascii
    $s14 = "n'; }; function npnc() { rrk += ' xa.'; }; function gxbb() { rrk += '=\"+st'; }; function hixn() { rrk += 'eToF'; }; function nb" ascii
    $s15 = "n fril() { rrk += 'er'; }; function ewg() { rrk += 're'; }; function ulr() { rrk += '; xa.'; }; function bys() { rrk += 'P\"); '" ascii
    $s16 = "= 'xa.si'; }; function lph() { rrk += 'e\"; v'; }; function mem() { rrk += ' WScr'; }; function lovc() { rrk += '1,0);'; }; func" ascii
    $s17 = "ekim() { rrk += 'll\");'; }; function qwda() { rrk += 'und('; }; function tukd() { wjk += 'val'; };  function ltu() { rrk += ' f" ascii
    $s18 = "ion trgx() { rrk += 'funct'; }; function hbzn() { rrk += '; };'; }; function axe() { rrk += 'hange'; }; function hnph() { rrk +=" ascii
    $s19 = "rrk += 'ar'; }; function zeit() { rrk += 'lengt'; }; function vbz() { ypo = this[wjk]; };  function qfnn() { rrk += 'ega'; }; fu" ascii
    $s20 = "u() { rrk += 'seB'; }; function tfj() { rrk += '}; t'; }; function upwl() { rrk += 'ipt'; }; function ohoy() { rrk += 'WScr'; };" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}