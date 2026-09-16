rule _20160921_016aab466e10a29b831eb85b27664027_20160921_1c5a439961f0_4110 {
  meta:
    description = "datamaliciousorder - from files 20160921_016aab466e10a29b831eb85b27664027.js, 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a541dd7e97eedc43f6bcf89f007176352c81c1d1240a76218e73cf5bb3b171"
    hash2       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash3       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = ",(function f000(){return \"Km\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){re" ascii
    $s2 = "\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(function f" ascii
    $s3 = "\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f" ascii
    $s4 = "n f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"W" ascii
    $s5 = "\"EZu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}