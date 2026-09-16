rule sig_20151012_67dec9af48776f8880d1ae022a87f1c9 {
  meta:
    description = "datamaliciousorder - file 20151012_67dec9af48776f8880d1ae022a87f1c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69191395ea55e54cf9311da097944b5c9825d242bb2c7744e8a464e92023fa51"

  strings:
    $s1  = "var str=\"5551575E0508010724011C1405101001070C4A070B095E225E08010A17120D0113174A0A085E17011614565E55505050525553555D54\"; functi" ascii
    $s2  = " function ufjw() { nxez += '(\"'; }; function yjyg() { nxez += 'GET\",'; }; function ssg() { nxez += '{};'; }; function cpd() { " ascii
    $s3  = " nxez += '{}'; }; function rpwa() { nxez += 'h (e'; }; function lng() { nxez += '.s'; }; function nxmo() { nxez += '.typ'; }; fu" ascii
    $s4  = "n zrpq() { nxez += '2.XML'; }; function jbdn() { nxez += 'dn = '; }; function hvl() { nxez += 'e = '; }; function ebg() { nxez +" ascii
    $s5  = "pl'; }; function zktc() { nxez += 'r xo'; }; function xla() { nxez += '(xo'; }; function decv() { nxez += 'com\"'; }; function a" ascii
    $s6  = "ez += 'Obje'; }; function ukpf() { ryn(nxez); };  var arge = ''; function lcl() { nxez += 'o.onr'; }; function wst() { nxez += '" ascii
    $s7  = "ction rgf() { nxez += 'eat'; }; function rzl() { nxez += ' if '; }; function uicn() { nxez += '4 && '; }; function uoi() { nxez " ascii
    $s8  = "}; '; }; function txhd() { nxez += '); }'; }; function qngp() { nxez += ' { i'; }; function gnhb() { nxez += 'Ex'; }; function v" ascii
    $s9  = ") { nxez += '0) { '; }; function ywmi() { nxez += '};'; }; function nsh() { nxez += 'e = 1'; }; function rua() { nxez += '1); d'" ascii
    $s10 = " nxez += 'n()'; }; function ilcu() { nxez += 'ip'; }; function hlz() { nxez += 'Cr'; }; function leg() { nxez += 'sta'; }; funct" ascii
    $s11 = "+= '0);'; }; function plno() { nxez += '(e'; }; function drho() { nxez += 'var'; }; function yqxv() { nxez += '(fr)'; }; functio" ascii
    $s12 = "var str=\"5551575E0508010724011C1405101001070C4A070B095E225E08010A17120D0113174A0A085E17011614565E55505050525553555D54\"; functi" ascii
    $s13 = "= '+St'; }; function gmro() { nxez += '; }; '; }; function hmb() { nxez += 'cr'; }; function cejj() { nxez += 'iron'; }; functio" ascii
    $s14 = " 'r, fa'; }; function lnr() { nxez += 't(\"WS'; }; function qpp() { nxez += 'Body)'; }; function rqds() { nxez += 'nal'; }; func" ascii
    $s15 = "onwe() { nxez += 'ri'; }; var nxez = ''; function ued() { nxez += 'a.po'; }; function nfy() { nxez += 'r) '; }; function syi() {" ascii
    $s16 = "= 't.Cr'; }; function ooq() { nxez += '.Shel'; }; function enmo() { nxez += ' xa.'; }; function skp() { arge += 'val'; };  funct" ascii
    $s17 = "xez += 'pen(\"'; }; function jtnz() { nxez += 'h.ra'; }; function ngyo() { nxez += 'se'; }; function twq() { nxez += ' x'; }; fu" ascii
    $s18 = " { nxez += 'eObje'; }; function tsgl() { nxez += '(x'; }; function rijo() { nxez += 'ri'; }; function zne() { nxez += 'ct'; }; f" ascii
    $s19 = "unction mhjj() { nxez += 'WSc'; }; function gkc() { nxez += '= \"'; }; function dyd() { nxez += '+\"'; }; function tnaj() { nxez" ascii
    $s20 = "; }; function fwun() { nxez += 'e);'; }; function gcdx() { nxez += 'ar b '; }; function uhx() { nxez += 'cn'; }; function jexn()" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}