rule TTP_XOR_QUAD_CurrentVersionRun_aaaf {
  strings:
    $key_aaaf = { f9 c0 [2] dd ce [2] f6 e2 [2] d8 c0 [2] cc db [2] c3 c1 [2] dd dc [2] df dd [2] c4 db [2] d8 dc [2] c4 f3 }

  condition:
    any of them
}