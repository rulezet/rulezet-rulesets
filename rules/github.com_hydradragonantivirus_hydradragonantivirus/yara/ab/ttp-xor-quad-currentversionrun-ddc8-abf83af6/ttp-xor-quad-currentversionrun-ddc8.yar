rule TTP_XOR_QUAD_CurrentVersionRun_ddc8 {
  strings:
    $key_ddc8 = { 8e a7 [2] aa a9 [2] 81 85 [2] af a7 [2] bb bc [2] b4 a6 [2] aa bb [2] a8 ba [2] b3 bc [2] af bb [2] b3 94 }

  condition:
    any of them
}