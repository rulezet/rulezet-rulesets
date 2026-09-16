rule TTP_XOR_QUAD_CurrentVersionRun_b0a5 {
  strings:
    $key_b0a5 = { e3 ca [2] c7 c4 [2] ec e8 [2] c2 ca [2] d6 d1 [2] d9 cb [2] c7 d6 [2] c5 d7 [2] de d1 [2] c2 d6 [2] de f9 }

  condition:
    any of them
}