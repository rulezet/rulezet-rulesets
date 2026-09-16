rule _20160921_a977d2870f5e9d12c659565b82cfaa70_20160921_c6572694e517_5615 {
  meta:
    description = "datamaliciousorder - from files 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c6572694e5172932491036c67fc9ffe4.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash2       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"
    hash3       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1 = ";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"RPt\";})(),(function f0" ascii
    $s2 = " \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"HJm\";})(),(fu" ascii
    $s3 = "000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg" ascii
    $s4 = ",(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Lo\";})(),(function f000(){" ascii
    $s5 = "ction f000(){return \"BMj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}