rule sig_20151025_90a52e598bb96c2f0663feca22a76710 {
  meta:
    description = "datamaliciousorder - file 20151025_90a52e598bb96c2f0663feca22a76710.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97a55f931a50eca2d654bd71ba5d588567c02949b0952e75a44e987b110a1baa"

  strings:
    $s1  = "var str=\"55515C5E160D1005240C160A0111160B14014A070B095E275E160B070C01080D01164A070B095E17555E555050515352545D505D5E55\"; functi" ascii
    $s2  = "}; function vox() { zdz += 'a.'; }; function minx() { zdz += '//\"+b'; }; function cmd() { zdz += 'ry { '; }; function jma() { z" ascii
    $s3  = "on tpdi() { zdz += 'GET\"'; }; function msj() { zdz += 'kwo'; }; function uznw() { zdz += 'te'; }; function afx() { zdz += 'id';" ascii
    $s4  = " zdz += 'ar '; }; function fnac() { zdz += 'ready'; }; function epl() { zdz += 'dn '; }; function rfj() { zdz += '000'; }; funct" ascii
    $s5  = "function fmm() { zdz += '.sta'; }; function uzgj() { zdz += 'gs(\"'; }; function piv() { zdz += 'rk.c'; }; function pmg() { zdz " ascii
    $s6  = "; }; function fmtm() { zdz += 'oFile'; }; function gtgv() { zdz += 'tus'; }; function ffrv() { zdz += 'r '; }; function pxuu() {" ascii
    $s7  = "on pqkr() { zdz += 'fn+n+'; }; function zusy() { zdz += 'saveT'; }; function iwer() { zdz += ' xa.'; }; function cebv() { zdz +=" ascii
    $s8  = "czx() { zdz += ' }'; }; function vmmt() { zdz += 'Sc'; }; function boxv() { zdz += 't.Cr'; }; function uhj() { zdz += 'alse'; };" ascii
    $s9  = "yyp() { zdz += 'ws.Ru'; }; function erfv() { zdz += 'xo.re'; }; function lot() { zdz += 'ears'; }; function dzzh() { zdz += ' ='" ascii
    $s10 = "var str=\"55515C5E160D1005240C160A0111160B14014A070B095E275E160B070C01080D01164A070B095E17555E555050515352545D505D5E55\"; functi" ascii
    $s11 = "= 'if'; }; function kpax() { zdz += '); va'; }; function euxj() { zdz += 'var f'; }; function ghws() { zdz += 'or'; }; function " ascii
    $s12 = " bqhp() { zdz += 'cl'; }; function pnbs() { zdz += ' 200)'; }; function vne() { zdz += 'EMP%'; }; function cyse() { zdz += 'ng';" ascii
    $s13 = "n fkg() { zdz += 'ri'; }; function tyqk() { zdz += 'ent'; }; function ria() { zdz += 'Strin'; }; function usrf() { zdz += 'dn ='" ascii
    $s14 = "qj() { zdz += 'n = '; }; function qemc() { bmi = nbhm[rah]; };  function jja() { zdz += 'st'; }; function zwcl() { zdz += 'i<'; " ascii
    $s15 = "z += 'om ds'; }; function jkuf() { zdz += '> 1'; }; function ccsi() { zdz += ',2'; }; function hjtc() { zdz += 'MLHTT'; }; funct" ascii
    $s16 = " { zdz += 'o.uk '; }; function xfjp() { zdz += 'at.c'; }; function wzyq() { zdz += 'ndE'; }; function vihe() { zdz += '= 1;'; };" ascii
    $s17 = "nction upp() { zdz += ') { }'; }; function qwpb() { zdz += 'rip'; }; function bbqr() { zdz += 'exe\"'; }; function vswl() { zdz " ascii
    $s18 = " }; function gkyu() { zdz += 'Scri'; }; function csqj() { zdz += ' xo.'; }; function hsl() { zdz += 'andp'; }; function vlqs() {" ascii
    $s19 = " awra() { zdz += 'n('; }; function mjm() { zdz += 'n+'; }; function xrqg() { zdz += 'os'; }; function tla() { zdz += '()'; }; fu" ascii
    $s20 = "; }; function zccd() { zdz += 'or ('; }; function veg() { zdz += 'DB.'; }; function qcvq() { zdz += 'it'; }; function lju() { zd" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}