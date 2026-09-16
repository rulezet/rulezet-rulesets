rule TTP_XOR_QUAD_CurrentVersionRun_d7c6 {
  strings:
    $key_d7c6 = { 84 a9 [2] a0 a7 [2] 8b 8b [2] a5 a9 [2] b1 b2 [2] be a8 [2] a0 b5 [2] a2 b4 [2] b9 b2 [2] a5 b5 [2] b9 9a }

  condition:
    any of them
}