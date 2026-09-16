rule _20160921_a977d2870f5e9d12c659565b82cfaa70_20160921_c6572694e517_4017 {
  meta:
    description = "datamaliciousorder - from files 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c6572694e5172932491036c67fc9ffe4.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash2       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"
    hash3       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = "\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f" ascii
    $s2 = "f000(){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s3 = "on f000(){return \"Yv\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"" ascii
    $s4 = "return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(" ascii
    $s5 = "unction f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){ret" ascii
    $s6 = "turn \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}