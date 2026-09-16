rule TTP_XOR_QUAD_CurrentVersionRun_d7d6 {
  strings:
    $key_d7d6 = { 84 b9 [2] a0 b7 [2] 8b 9b [2] a5 b9 [2] b1 a2 [2] be b8 [2] a0 a5 [2] a2 a4 [2] b9 a2 [2] a5 a5 [2] b9 8a }

  condition:
    any of them
}