rule _20160921_2fddda42e5911e6501568e734d430149_20160921_9ed8ba5d12b4_3591 {
  meta:
    description = "datamaliciousorder - from files 20160921_2fddda42e5911e6501568e734d430149.js, 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"
    hash2       = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"

  strings:
    $s1 = ")(),(function f000(){return \"Qa\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(" ascii
    $s2 = "){return \"EZu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Rh\";}" ascii
    $s3 = "\"PTs\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s4 = "rn \"NYh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(fun" ascii
    $s5 = "00(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn" ascii
    $s6 = "ction f000(){return \"Wy\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Lo\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}