rule TTP_XOR_QUAD_CurrentVersionRun_b0a4 {
  strings:
    $key_b0a4 = { e3 cb [2] c7 c5 [2] ec e9 [2] c2 cb [2] d6 d0 [2] d9 ca [2] c7 d7 [2] c5 d6 [2] de d0 [2] c2 d7 [2] de f8 }

  condition:
    any of them
}