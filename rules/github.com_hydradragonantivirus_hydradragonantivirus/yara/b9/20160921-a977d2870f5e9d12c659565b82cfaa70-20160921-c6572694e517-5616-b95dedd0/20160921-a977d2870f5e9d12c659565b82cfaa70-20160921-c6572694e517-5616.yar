rule _20160921_a977d2870f5e9d12c659565b82cfaa70_20160921_c6572694e517_5616 {
  meta:
    description = "datamaliciousorder - from files 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c6572694e5172932491036c67fc9ffe4.js, 20160921_cb6c4de61b30cd204129d0942321058c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash2       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"
    hash3       = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"

  strings:
    $s1 = "n f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"X" ascii
    $s2 = "ion f000(){return \"Yv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s3 = "nction f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){retur" ascii
    $s4 = "on f000(){return \"BMj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s5 = "eturn \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}