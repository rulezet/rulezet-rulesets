rule sig_20170125_bf7a18bac304db6cb44442a7422b6b3e {
  meta:
    description = "datamaliciousorder - file 20170125_bf7a18bac304db6cb44442a7422b6b3e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54b4c42264246252a93d88962e0cc1613446d22e941c4e5a9b38e7b517236d39"

  strings:
    $s1  = "function xevhuvqossenogunbovabbehtunsijycdaskujewozizuhivyfdabedumpiwwufomro() {" fullword ascii
    $s2  = "var yvukbawteth = egykdakpirojozryxsibtocxuqdadlevxahogjugmamxizlucwyzkagzogelogverufupoqikikyknyvbywedoxvacrejosydvikegerexewgo" ascii
    $s3  = "function egykdakpirojozryxsibtocxuqdadlevxahogjugmamxizlucwyzkagzogelogverufupoqikikyknyvbywedoxvacrejosydvikegerexewgoxquvacsuv" ascii
    $s4  = "return [ /*unw*/ , /*ijmy*/ , \"C:\\\\\", /*um*/ ];" fullword ascii
    $s5  = "return [ /*emvom*/ , /*he*/ , /*cvi*/ , /*eml*/ , WScript, /*jipr*/ , /*ily*/ , /*pa*/ ][4];" fullword ascii
    $s6  = "return [ /*iqka*/ , \"Get\"];" fullword ascii
    $s7  = "return [\"Get\", /*ujyb*/ ];" fullword ascii
    $s8  = "function vozajubujilogabpesuwgawfunbubnexonpancejxivopogladarepvikixmyvwa() {" fullword ascii
    $s9  = "return [\"cmd\", /*dorl*/ ];" fullword ascii
    $s10 = "return [ /*am*/ , /*ikko*/ , \"Get\", /*cdo*/ ];" fullword ascii
    $s11 = "function nujekvewovfibefpusjimduvgetubduvqytykadtohelzyfezyzaqwocilujyxi() {" fullword ascii
    $s12 = "function egykdakpirojozryxsibtocxuqdadlevxahogjugmamxizlucwyzkagzogelogverufupoqikikyknyvbywedoxvacrejosydvikegerexewgoxquvacsuv" ascii
    $s13 = "function danegqusaguqnazamutimiqoxgazpezoqfemguspyxelropmebfefexxaqoka() {" fullword ascii
    $s14 = "function owpedvaxabakhygritqofisahilelevespynceqbofurkorcejombipceruxrefkawtetzocyqlodgarugolparw() {" fullword ascii
    $s15 = "//var ljagxeg = zuny0[yxlyfxaqdyfuqgusasactoqecegacuzarwaphojkulnoftezicovywosuhyzhadm()[[ /*raga*/ , 1, /*dyddu*/ ][1]] + exoke" ascii
    $s16 = "[3]] + xluztyhtynifwycjebifivjubotobegufabojukfynsilqywqoruwocqyfezafzesrohifahsip()[[ /*dote*/ , 0, /*og*/ , /*jjajd*/ , /*huk*" ascii
    $s17 = "*/ , /*ycwif*/ , /*nowy*/ ][1]] + irhatewmapxivvyrpefoculisnatcifecnijjyxbapekivhilynerisyqjyjymbafmahkavz()[[1, /*pyty*/ , /*oh" ascii
    $s18 = "function xejyvmimsiluwgyvyfrycubzyvuhetxakwuduxnifehyjyqsubxowruniqdarmorfafmodexjud() {" fullword ascii
    $s19 = "function usuwinufpycnydiplulrivcutdijyvcisperkaxisydmogaknalbinfelytxejgizomsy() {" fullword ascii
    $s20 = "return [ /*iq*/ , /*idi*/ , \"run\", /*uhn*/ ];" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}