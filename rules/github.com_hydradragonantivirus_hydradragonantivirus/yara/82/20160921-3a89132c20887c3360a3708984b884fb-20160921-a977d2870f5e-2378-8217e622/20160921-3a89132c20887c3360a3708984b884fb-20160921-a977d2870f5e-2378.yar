rule _20160921_3a89132c20887c3360a3708984b884fb_20160921_a977d2870f5e_2378 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c6572694e5172932491036c67fc9ffe4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash2       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash3       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"

  strings:
    $s1 = "nction f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii
    $s2 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"IAa\";})(),(function f000(" ascii
    $s3 = "(){return \"XTn\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})" ascii
    $s4 = "urn \"MBb\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"DIa\";})(),(" ascii
    $s5 = "})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f00" ascii
    $s6 = "eturn \"MDb\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Km\";})()," ascii
    $s7 = ")(),(function f000(){return \"SEo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000" ascii
    $s8 = "0(){return \"TKl\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}