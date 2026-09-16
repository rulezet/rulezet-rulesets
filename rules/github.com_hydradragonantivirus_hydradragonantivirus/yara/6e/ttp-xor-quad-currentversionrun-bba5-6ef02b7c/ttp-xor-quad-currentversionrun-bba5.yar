rule TTP_XOR_QUAD_CurrentVersionRun_bba5 {
  strings:
    $key_bba5 = { e8 ca [2] cc c4 [2] e7 e8 [2] c9 ca [2] dd d1 [2] d2 cb [2] cc d6 [2] ce d7 [2] d5 d1 [2] c9 d6 [2] d5 f9 }

  condition:
    any of them
}