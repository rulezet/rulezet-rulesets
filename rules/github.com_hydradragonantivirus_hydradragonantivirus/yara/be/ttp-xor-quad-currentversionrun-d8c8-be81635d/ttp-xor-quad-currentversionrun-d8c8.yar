rule TTP_XOR_QUAD_CurrentVersionRun_d8c8 {
  strings:
    $key_d8c8 = { 8b a7 [2] af a9 [2] 84 85 [2] aa a7 [2] be bc [2] b1 a6 [2] af bb [2] ad ba [2] b6 bc [2] aa bb [2] b6 94 }

  condition:
    any of them
}