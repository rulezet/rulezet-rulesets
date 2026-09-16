rule sig_20151004_af4b9a80c89453cde0c9634e3aeb5ba0 {
  meta:
    description = "datamaliciousorder - file 20151004_af4b9a80c89453cde0c9634e3aeb5ba0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3170ea65e1e8e823528f5fa4c4d0a7a91469f35aa47fc762ea6014af2698cd4f"

  strings:
    $s1  = "var str=\"5551555E0D0A020B24011C1405101001070C4A070B095E225E0D1001070C170B0811100D0B0A174A100A5E17011614565E555050575D5C51505556" ascii
    $s2  = " 4 &'; }; function hyg() { lgdn += 'ready'; }; function tvo() { lgdn += 'un('; }; function gjh() { lgdn += 'reate'; }; function " ascii
    $s3  = "+= 'om'; }; function nbt() { lgdn += 'var '; }; function dud() { lgdn += '}; '; }; function mql() { lgdn += '.wri'; }; function " ascii
    $s4  = "() { lgdn += ' 0;'; }; function dqh() { lgdn += '{ '; }; function nxy() { lgdn += 'WSc'; }; function jnd() { lgdn += '; xa.'; };" ascii
    $s5  = "{ lgdn += ' var'; }; function vpcm() { lgdn += 'ose'; }; function zvyk() { lgdn += 'cri'; }; function bqk() { lgdn += ' = W'; };" ascii
    $s6  = "ea'; }; function imyg() { lgdn += '; xa.'; }; function amhg() { lgdn += ' sam'; }; function qiih() { lgdn += 'at'; }; function j" ascii
    $s7  = "&i'; }; function bcp() { lgdn += 'ur'; }; function qzd() { lgdn += 'nc'; }; function bhy() { lgdn += '= '; }; function ethf() { " ascii
    $s8  = "'; }; function grx() { lgdn += ' fal'; }; function hryr() { lgdn += 'o.Re'; }; function urp() { lgdn += 'DB'; }; function nkc() " ascii
    $s9  = "n += 'r x'; }; function creg() { lgdn += '; xo'; }; function moxu() { lgdn += 'WS'; }; function wfhq() { lgdn += ' ='; }; functi" ascii
    $s10 = "{ lgdn += ' dl(f'; }; function qnub() { lgdn += 'pt.'; }; var yckg = ''; function swom() { lgdn += '.on'; }; function foq() { lg" ascii
    $s11 = "n yvm() { lgdn += ' ww'; }; function jlc() { lgdn += '.co'; }; function qtlp() { lgdn += 't(\"'; }; function etyg() { lgdn += '+" ascii
    $s12 = "unction owy() { lgdn += '.S'; }; function gmwy() { lgdn += 're'; }; function bccb() { lgdn += '() {'; }; function qxpt() { lgdn " ascii
    $s13 = "n += '; if'; }; function wbdh() { lgdn += '= fu'; }; function fby() { lgdn += 'tion'; }; function vwk() { lgdn += 'fo'; }; funct" ascii
    $s14 = " lgdn += 'lName'; }; function qxon() { lgdn += 'd=\"'; }; function sto() { lgdn += 'sz'; }; function iesq() { lgdn += 'exe\";'; " ascii
    $s15 = " lgdn += '; xa'; }; function vkq() { yckg(lgdn); };  function xrd() { lgdn += 'ocum'; }; function flas() { lgdn += ' va'; }; fun" ascii
    $s16 = "dn += 'y { w'; }; function mrv() { lgdn += '+b[i'; }; function udxv() { lgdn += 'se); '; }; function tntx() { lgdn += 'veT'; };r" ascii
    $s17 = "lgdn += ' v'; }; function nvr() { lgdn += ') {'; }; function cnfp() { lgdn += 'reate'; }; function bmhy() { lgdn += 'open'; }; f" ascii
    $s18 = " function wyfw() { lgdn += ' (dn'; }; function htl() { lgdn += 'te(x'; }; function mhno() { lgdn += '1; xa'; }; function yam() {" ascii
    $s19 = "E56\"; function jypm() { lgdn += 'p?rn'; }; function mlco() { lgdn += 'th.r'; }; function jji() { lgdn += 's.R'; }; function irk" ascii
    $s20 = "on rol() { lgdn += 'fu'; }; function njjp() { lgdn += 'Scri'; }; function ykh() { lgdn += '.Shel'; }; function azd() { lgdn += '" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}