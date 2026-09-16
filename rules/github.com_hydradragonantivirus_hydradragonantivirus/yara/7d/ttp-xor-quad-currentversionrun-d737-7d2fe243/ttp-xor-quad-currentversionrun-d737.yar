rule TTP_XOR_QUAD_CurrentVersionRun_d737 {
  strings:
    $key_d737 = { 84 58 [2] a0 56 [2] 8b 7a [2] a5 58 [2] b1 43 [2] be 59 [2] a0 44 [2] a2 45 [2] b9 43 [2] a5 44 [2] b9 6b }

  condition:
    any of them
}