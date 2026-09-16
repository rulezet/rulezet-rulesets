rule sig_20151019_f3f28c108ca65761a324189f38357278 {
  meta:
    description = "datamaliciousorder - file 20151019_f3f28c108ca65761a324189f38357278.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73009e6972f8cd85e2aac6222c12802704eba3822652619d8355a30ca462b6a0"

  strings:
    $s1  = "var str=\"5551525E0C160A240C160A0111160B14014A070B095E275E0108010710160B0A0D0705491601120D0113174A0A085E17555E555050515652575253" ascii
    $s2  = "= 'xo '; }; function knjm() { muu += ' xa.p'; }; function bfeg() { muu += 'GET'; }; function pibe() { muu += ' if '; }; function" ascii
    $s3  = "= '.Exp'; }; function cdk() { muu += '); '; }; function yet() { muu += ',2); '; }; function iqq() { muu += '= '; }; function gkf" ascii
    $s4  = "gzz() { muu += '); dl'; }; function nxxu() { muu += 'pen(\"'; }; function nuk() { muu += 'is'; }; function jatl() { muu += '.org" ascii
    $s5  = "function tzsy() { muu += 'dl('; }; function cqn() { muu += '.Cre'; }; function rksp() { muu += '/\"+'; }; function dwru() { muu " ascii
    $s6  = "() { muu += '67'; }; var pnlb = ''; function cubs() { muu += '.Cre'; }; function plkr() { muu += 'nre'; }; function ewpj() { pnl" ascii
    $s7  = " psd() { muu += 'n('; }; function frm() { muu += '%T'; }; function gye() { muu += '200) '; }; function vqct() { muu += '.ope'; }" ascii
    $s8  = "n inf() { muu += '.Str'; }; function ebb() { muu += 't.C'; }; function grf() { muu += 'xa.'; }; function gio() { ezc = xweh[pnlb" ascii
    $s9  = "tion dqfd() { muu += 'tatec'; }; function nmlp() { muu += 'Run(f'; }; function jpv() { muu += 'tp:/'; }; function lslg() { muu +" ascii
    $s10 = ") { muu += 't.'; }; function juwu() { muu += '.ty'; }; function skel() { muu += 'r xa '; }; function ggqr() { muu += 'TT'; }; fu" ascii
    $s11 = "n dbb() { muu += 'dl(fr'; }; function vjwt() { muu += 'DODB'; }; function tdqe() { muu += ') {'; }; function orls() { muu += 'ir" ascii
    $s12 = "on raz() { muu += 'r/?id'; }; function mqzm() { muu += '3)'; }; function upq() { muu += '31.5'; }; function roys() { muu += 'cri" ascii
    $s13 = " { muu += 'al'; }; function fny() { muu += '6.233'; }; function gpv() { muu += '; '; }; function ebs() { muu += 'adys'; }; funct" ascii
    $s14 = "r '; }; function qno() { muu += 'er'; }; function svet() { muu += 'a.wr'; }; function cky() { muu += '=0;'; }; function gygm() {" ascii
    $s15 = " += 'EM'; }; var ezc = ''; function fow() { muu += 'eO'; }; function tvj() { muu += 'e > 1'; }; function bjyw() { muu += 'siz'; " ascii
    $s16 = "p'; }; function pera() { muu += 'tc'; }; function wjw() { muu += ' xa'; }; function wxfp() { muu += 'ion '; }; function zte() { " ascii
    $s17 = "ion lihk() { muu += '52'; }; function fus() { muu += '000'; }; function ret() { muu += ' isla'; }; function erwl() { muu += '1,0" ascii
    $s18 = "fn() { muu += 'L2.XM'; }; function aqvs() { ezc(muu); };  function mshu() { muu += '= '; }; function suy() { muu += ' {}; '; }; " ascii
    $s19 = "'; }; function yiaj() { muu += '(92)'; }; function jwk() { muu += 'li'; }; function mhrc() { muu += '}; };'; }; function dcm() {" ascii
    $s20 = "; }; function jqyu() { muu += 'pe ='; }; function zyw() { muu += 'ons'; }; function nsjb() { muu += 'a.cl'; }; function hxla() {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}