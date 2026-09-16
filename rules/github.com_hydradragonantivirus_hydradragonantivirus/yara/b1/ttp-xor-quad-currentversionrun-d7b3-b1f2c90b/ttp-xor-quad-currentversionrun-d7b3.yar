rule TTP_XOR_QUAD_CurrentVersionRun_d7b3 {
  strings:
    $key_d7b3 = { 84 dc [2] a0 d2 [2] 8b fe [2] a5 dc [2] b1 c7 [2] be dd [2] a0 c0 [2] a2 c1 [2] b9 c7 [2] a5 c0 [2] b9 ef }

  condition:
    any of them
}