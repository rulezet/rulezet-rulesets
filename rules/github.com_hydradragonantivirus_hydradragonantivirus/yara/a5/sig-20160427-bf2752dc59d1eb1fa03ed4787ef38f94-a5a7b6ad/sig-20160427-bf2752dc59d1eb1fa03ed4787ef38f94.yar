rule sig_20160427_bf2752dc59d1eb1fa03ed4787ef38f94 {
  meta:
    description = "datamaliciousorder - file 20160427_bf2752dc59d1eb1fa03ed4787ef38f94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12de740fd3bb4634c98763fb02bbebec32b6c94ea7764bfec7fdb5c27e2163b3"

  strings:
    $s1  = "}switch(false) {" fullword ascii
    $s2  = " if(1 === true) {" fullword ascii
    $s3  = " if(5 == true) {" fullword ascii
    $s4  = " if(3 == false) {" fullword ascii
    $s5  = "}switch(true) {" fullword ascii
    $s6  = " var rrera = false; " fullword ascii
    $s7  = " var KXsXZql = false; " fullword ascii
    $s8  = "}function isKSlG (GOavg,RWpu,WkP) {" fullword ascii
    $s9  = "switch(MFCgB) {" fullword ascii
    $s10 = "function WxZqE () {" fullword ascii
    $s11 = " var lnUKCwT = true; " fullword ascii
    $s12 = "function bnS () {" fullword ascii
    $s13 = " if(UnJvp === true) {" fullword ascii
    $s14 = " var MbbiTui = false; " fullword ascii
    $s15 = " var MaRIN = true; " fullword ascii
    $s16 = " var mQeP = false; " fullword ascii
    $s17 = "return 1;}function BOFa (qNAlDzMa) {" fullword ascii
    $s18 = "function ZZAmA (RQDH) {" fullword ascii
    $s19 = "} var gNhwNq = true; " fullword ascii
    $s20 = " var KNUBo = true; " fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}