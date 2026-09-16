rule _20160921_619a314e9bcca286c046dff250b54b6b_20160921_fff847efa0ea_5300 {
  meta:
    description = "datamaliciousorder - from files 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_fff847efa0eaa326a0aad4d2fc81d41e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash2       = "93f868a10878cb41f305e28c8802778903c99b84a1bc0647a0c2c78fd6310577"

  strings:
    $s1 = "(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})" ascii
    $s2 = "\"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(funct" ascii
    $s3 = "return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(" ascii
    $s4 = " \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt\";})(),(fun" ascii
    $s5 = "urn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}