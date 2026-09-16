rule _20160921_619a314e9bcca286c046dff250b54b6b_20160921_802181e3d75c_5298 {
  meta:
    description = "datamaliciousorder - from files 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_802181e3d75c3e2d045cebba97849683.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash2       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"

  strings:
    $s1 = "})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f00" ascii
    $s2 = "eturn \"Qa\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s3 = ")(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000" ascii
    $s4 = "(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Qa\";})(),(function f000(){re" ascii
    $s5 = " f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"D" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}