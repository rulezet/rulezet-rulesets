rule TTP_XOR_QUAD_CurrentVersionRun_d746 {
  strings:
    $key_d746 = { 84 29 [2] a0 27 [2] 8b 0b [2] a5 29 [2] b1 32 [2] be 28 [2] a0 35 [2] a2 34 [2] b9 32 [2] a5 35 [2] b9 1a }

  condition:
    any of them
}