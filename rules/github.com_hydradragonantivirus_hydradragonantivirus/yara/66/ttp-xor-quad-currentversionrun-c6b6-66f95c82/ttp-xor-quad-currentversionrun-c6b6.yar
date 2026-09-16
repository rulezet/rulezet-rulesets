rule TTP_XOR_QUAD_CurrentVersionRun_c6b6 {
  strings:
    $key_c6b6 = { 95 d9 [2] b1 d7 [2] 9a fb [2] b4 d9 [2] a0 c2 [2] af d8 [2] b1 c5 [2] b3 c4 [2] a8 c2 [2] b4 c5 [2] a8 ea }

  condition:
    any of them
}