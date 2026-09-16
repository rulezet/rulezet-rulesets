rule _20160921_38347709a1c3747cfb23ae60221ea7bf_20160921_3a2902eaca0b_4944 {
  meta:
    description = "datamaliciousorder - from files 20160921_38347709a1c3747cfb23ae60221ea7bf.js, 20160921_3a2902eaca0b2b91120958418b46c844.js, 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js, 20160921_5f14ae6f169c53d6d49523d1e13e4ab9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39473c48023f5000ce36bdc645860556dc6b5f3b0022f86190a49370f4633bbc"
    hash2       = "063bab1922376d926db97bdcd4342c2e9b0f2ec98d9fad81c2a3f86537c82b07"
    hash3       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"
    hash4       = "270eb53363684986d2aef11b6b5bb4cd5c5cb316f626e41b627db2cf899b440e"

  strings:
    $s1 = ",(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){r" ascii
    $s2 = "turn \"CCb\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"XFd\";})(),(" ascii
    $s3 = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MUs\";})" ascii
    $s4 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retur" ascii
    $s5 = "return \"Hs\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}