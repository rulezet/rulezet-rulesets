rule _20160921_0fe6501a0417801a0e1868963016e9be_20160922_433c067ed379_4372 {
  meta:
    description = "datamaliciousorder - from files 20160921_0fe6501a0417801a0e1868963016e9be.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2926229ccbf6b86ba0ed1aa3ab5b137a43467ffe25d09479a7998c2fdc4b2b30"
    hash2       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash3       = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1 = "urn \"Do\";})(),(function f000(){return \"MKa\";})()];" fullword ascii
    $s2 = "urn \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s3 = " \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s4 = "TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s5 = "on f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}