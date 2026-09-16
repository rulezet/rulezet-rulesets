rule _20160921_13c992e435ed245b1977cea0df2db815_20160921_319493db332e_3378 {
  meta:
    description = "datamaliciousorder - from files 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_319493db332e8496aaa88d74f25f0b8a.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash2       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"
    hash3       = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"
    hash4       = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"

  strings:
    $s1 = "00(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\"" ascii
    $s2 = "(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";" ascii
    $s3 = "GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(funct" ascii
    $s4 = "Gn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s5 = "Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s6 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}