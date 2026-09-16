rule _20160921_dff46b67b973e99ec02248f10c2f55c2_20160922_b22dda4c9fbc_3155 {
  meta:
    description = "datamaliciousorder - from files 20160921_dff46b67b973e99ec02248f10c2f55c2.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"
    hash2       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1 = "){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Do\";})" ascii
    $s2 = "GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(function" ascii
    $s3 = "Ml\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function" ascii
    $s4 = "urn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(" ascii
    $s5 = "ion f000(){return \"QDg\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DNa\";})(),(function f000(){return" ascii
    $s6 = "{return \"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(" ascii
    $s7 = "n \"Qa\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}