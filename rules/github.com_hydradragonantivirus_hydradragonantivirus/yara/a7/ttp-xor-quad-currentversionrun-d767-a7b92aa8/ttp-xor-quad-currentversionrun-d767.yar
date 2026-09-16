rule TTP_XOR_QUAD_CurrentVersionRun_d767 {
  strings:
    $key_d767 = { 84 08 [2] a0 06 [2] 8b 2a [2] a5 08 [2] b1 13 [2] be 09 [2] a0 14 [2] a2 15 [2] b9 13 [2] a5 14 [2] b9 3b }

  condition:
    any of them
}