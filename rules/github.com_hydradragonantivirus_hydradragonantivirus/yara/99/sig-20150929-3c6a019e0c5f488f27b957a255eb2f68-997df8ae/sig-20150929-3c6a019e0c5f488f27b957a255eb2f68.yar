rule sig_20150929_3c6a019e0c5f488f27b957a255eb2f68 {
  meta:
    description = "datamaliciousorder - file 20150929_3c6a019e0c5f488f27b957a255eb2f68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "872b67688f776388548b27277f2b8b6842ae2d3229c0d7002ddb5992d90d2866"

  strings:
    $s1  = "var str=\"55505C5E0B14011605100D0B0A17240C160A0111160B14014A070B095E225E000B130A080B0500091457080503110C0D10174A070B095E17011614" ascii
    $s2  = ") { knbtw += 'e = f'; }; function hhpeg() { knbtw += '.com '; }; function mckhfhb() { knbtw += '(92)+'; }; function nykeid() { k" ascii
    $s3  = ")'; }; function tjrjs() { knbtw += 'ra'; }; function ynvm() { knbtw += 's.Run'; }; function kfmp() { knbtw += '(); '; }; functio" ascii
    $s4  = "n utvhg() { knbtw += 'SX'; }; function oqiyhvf() { knbtw += '(\"GET'; }; function qkvrdv() { knbtw += '); '; };ssiwjqi(); hknjd(" ascii
    $s5  = "n foavs() { knbtw += '.read'; }; function dxtvdon() { knbtw += 'e\"'; }; function wzuf() { knbtw += '+fr+\"'; }; function ymsqrg" ascii
    $s6  = "ction oxgtbzm() { knbtw += '.Expa'; }; function arhyneg() { knbtw += 'com'; }; function bmxuc() { knbtw += 'ttp:/'; }; function " ascii
    $s7  = "ction ilpqu() { knbtw += 'men'; }; function ktsk() { knbtw += '.siz'; }; function twge() { knbtw += ' i<'; }; function evhugs() " ascii
    $s8  = "rxzrsq() { knbtw += 'xo.s'; }; function ybzuogw() { knbtw += 'ML2'; }; function dnnrszs() { knbtw += '&id=\"'; }; function dyyh(" ascii
    $s9  = "() { knbtw += 'li'; }; function mfmpo() { knbtw += '+\"/'; }; function ldztmjq() { knbtw += 'xo.op'; }; function wgax() { knbtw " ascii
    $s10 = "q() { knbtw += 'e('; }; function jwnjl() { knbtw += 'w A'; }; function izfbyy() { knbtw += '?r'; }; function ulfsc() { knbtw += " ascii
    $s11 = "nbtw += ' if '; }; function qcjdd() { knbtw += 'e =='; }; function grwz() { knbtw += 'tr, f'; }; function huskr() { knbtw += 'in" ascii
    $s12 = "gs('; }; function mebrty() { knbtw += 'trea'; }; function bnss() { knbtw += ' var'; }; function foyfx() { knbtw += '+St'; }; fun" ascii
    $s13 = "ju() { knbtw += ');'; }; function pyoqw() { knbtw += 'xa ='; }; function juhv() { knbtw += '= 1'; }; function itkqf() { knbtw +=" ascii
    $s14 = " { knbtw += 'on()'; }; function olzcz() { knbtw += '=0;'; }; function kbtqf() { knbtw += 'ODB.S'; }; function gpnr() { knbtw += " ascii
    $s15 = "print(knbtw);" fullword ascii
    $s16 = "n bwqopc() { knbtw += 'o '; }; function xwfsvbm() { knbtw += '\".sp'; }; function uecia() { knbtw += 'try '; }; function mlqbzdu" ascii
    $s17 = "nction xgscsay() { knbtw += 'f (xo'; }; function euwy() { knbtw += 'd()'; }; function qvjq() { knbtw += 'fr) {'; }; function cjp" ascii
    $s18 = "; }; function ggbaldq() { knbtw += 'Scri'; }; function jlnsll() { knbtw += ');'; }; function nirbx() { knbtw += 'en'; }; functio" ascii
    $s19 = " += 'cti'; }; function yswey() { knbtw += '+b[i]'; }; function ykzzv() { knbtw += 'gth'; }; function aqvzzb() { knbtw += ' {};';" ascii
    $s20 = "t.S'; }; function gddqs() { knbtw += ' Act'; }; function uofvz() { knbtw += ' if ('; }; function zkrf() { knbtw += 'tech'; }; fu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}