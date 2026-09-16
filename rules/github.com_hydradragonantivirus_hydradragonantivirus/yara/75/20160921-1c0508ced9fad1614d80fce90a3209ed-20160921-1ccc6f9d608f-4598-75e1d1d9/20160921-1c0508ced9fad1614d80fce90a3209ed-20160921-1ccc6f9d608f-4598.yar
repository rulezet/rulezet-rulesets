rule _20160921_1c0508ced9fad1614d80fce90a3209ed_20160921_1ccc6f9d608f_4598 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c0508ced9fad1614d80fce90a3209ed.js, 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e27406e32c891781b5403c718c4f32d67f6580cf6f952a30d0c6452ab9775a4c"
    hash2       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"

  strings:
    $s1 = "turn \"Do\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(" ascii
    $s2 = "f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"O" ascii
    $s3 = "(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\"" ascii
    $s4 = "urn \"EZu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(" ascii
    $s5 = "unction f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}