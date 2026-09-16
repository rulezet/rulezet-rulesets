rule _20160921_527d7c3756974f804734da343b6b6f0e_20160922_9d6af2734812_5175 {
  meta:
    description = "datamaliciousorder - from files 20160921_527d7c3756974f804734da343b6b6f0e.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d2dd725d314277b3b7cf1c94ae8894dce1d36430ff22819c2fecb47f14c3f43"
    hash2       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = "\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vu\";})(),(function f" ascii
    $s2 = " \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s3 = " \"Mc\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s4 = "),(function f000(){return \"Oh\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sj\";})(),(function f000(){" ascii
    $s5 = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}