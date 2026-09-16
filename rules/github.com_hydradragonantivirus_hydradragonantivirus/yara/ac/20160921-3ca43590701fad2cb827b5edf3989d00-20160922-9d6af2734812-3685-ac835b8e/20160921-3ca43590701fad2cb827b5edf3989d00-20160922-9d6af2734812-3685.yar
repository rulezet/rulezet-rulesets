rule _20160921_3ca43590701fad2cb827b5edf3989d00_20160922_9d6af2734812_3685 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ca43590701fad2cb827b5edf3989d00.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef7c5701a8646e7803463e9a01e4f2e45cd535f2ed7174e97abde991a779b665"
    hash2       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = "{return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Sq\";})(" ascii
    $s2 = "eturn \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(" ascii
    $s3 = "ion f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return" ascii
    $s4 = "rn \"Qa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s5 = "000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"XT" ascii
    $s6 = "return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}