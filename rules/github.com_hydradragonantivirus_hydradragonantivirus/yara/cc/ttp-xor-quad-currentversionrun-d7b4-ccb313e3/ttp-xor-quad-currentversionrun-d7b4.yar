rule TTP_XOR_QUAD_CurrentVersionRun_d7b4 {
  strings:
    $key_d7b4 = { 84 db [2] a0 d5 [2] 8b f9 [2] a5 db [2] b1 c0 [2] be da [2] a0 c7 [2] a2 c6 [2] b9 c0 [2] a5 c7 [2] b9 e8 }

  condition:
    any of them
}