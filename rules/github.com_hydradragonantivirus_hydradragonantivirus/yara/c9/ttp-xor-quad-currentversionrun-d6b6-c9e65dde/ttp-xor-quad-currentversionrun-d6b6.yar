rule TTP_XOR_QUAD_CurrentVersionRun_d6b6 {
  strings:
    $key_d6b6 = { 85 d9 [2] a1 d7 [2] 8a fb [2] a4 d9 [2] b0 c2 [2] bf d8 [2] a1 c5 [2] a3 c4 [2] b8 c2 [2] a4 c5 [2] b8 ea }

  condition:
    any of them
}