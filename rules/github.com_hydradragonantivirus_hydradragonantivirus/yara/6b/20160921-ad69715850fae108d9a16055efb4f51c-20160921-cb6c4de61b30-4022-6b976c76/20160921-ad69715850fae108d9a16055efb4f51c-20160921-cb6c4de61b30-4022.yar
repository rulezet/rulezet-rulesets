rule _20160921_ad69715850fae108d9a16055efb4f51c_20160921_cb6c4de61b30_4022 {
  meta:
    description = "datamaliciousorder - from files 20160921_ad69715850fae108d9a16055efb4f51c.js, 20160921_cb6c4de61b30cd204129d0942321058c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"
    hash2       = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"

  strings:
    $s1 = "\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f" ascii
    $s2 = "g\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function" ascii
    $s3 = "tion f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii
    $s4 = ")(),(function f000(){return \"Nv\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s5 = "n f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"" ascii
    $s6 = "rn \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}