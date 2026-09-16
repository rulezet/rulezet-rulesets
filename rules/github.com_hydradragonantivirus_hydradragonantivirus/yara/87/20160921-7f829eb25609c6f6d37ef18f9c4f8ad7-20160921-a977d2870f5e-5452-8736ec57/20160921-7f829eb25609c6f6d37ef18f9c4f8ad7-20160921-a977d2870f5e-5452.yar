rule _20160921_7f829eb25609c6f6d37ef18f9c4f8ad7_20160921_a977d2870f5e_5452 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js, 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c6572694e5172932491036c67fc9ffe4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"
    hash2       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash3       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"

  strings:
    $s1 = "0(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Km\";" ascii
    $s2 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s3 = "ction f000(){return \"Wb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return" ascii
    $s4 = "on f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s5 = "n f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"D" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}