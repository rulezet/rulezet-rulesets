rule _20160921_5d6863feab411af8217516a1b111aa40_20160921_a977d2870f5e_5253 {
  meta:
    description = "datamaliciousorder - from files 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c6572694e5172932491036c67fc9ffe4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash2       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash3       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"

  strings:
    $s1 = "})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f00" ascii
    $s2 = "\"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Br\";})(),(functi" ascii
    $s3 = " f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi" ascii
    $s4 = "Gn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Ml\";})(),(function " ascii
    $s5 = "n f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}