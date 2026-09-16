rule TTP_XOR_QUAD_CurrentVersionRun_d7b5 {
  strings:
    $key_d7b5 = { 84 da [2] a0 d4 [2] 8b f8 [2] a5 da [2] b1 c1 [2] be db [2] a0 c6 [2] a2 c7 [2] b9 c1 [2] a5 c6 [2] b9 e9 }

  condition:
    any of them
}