rule TTP_XOR_QUAD_CurrentVersionRun_d794 {
  strings:
    $key_d794 = { 84 fb [2] a0 f5 [2] 8b d9 [2] a5 fb [2] b1 e0 [2] be fa [2] a0 e7 [2] a2 e6 [2] b9 e0 [2] a5 e7 [2] b9 c8 }

  condition:
    any of them
}