rule _20160921_cf2bd9606d396ba99f8174f1946c8590_20160921_fff847efa0ea_5698 {
  meta:
    description = "datamaliciousorder - from files 20160921_cf2bd9606d396ba99f8174f1946c8590.js, 20160921_fff847efa0eaa326a0aad4d2fc81d41e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"
    hash2       = "93f868a10878cb41f305e28c8802778903c99b84a1bc0647a0c2c78fd6310577"

  strings:
    $s1 = ",(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(function f000(){r" ascii
    $s2 = "(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})" ascii
    $s3 = ",(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){r" ascii
    $s4 = "tion f000(){return \"Km\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s5 = "\"MMz\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}