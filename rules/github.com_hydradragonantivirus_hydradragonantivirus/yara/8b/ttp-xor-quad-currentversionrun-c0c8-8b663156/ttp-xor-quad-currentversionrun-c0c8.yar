rule TTP_XOR_QUAD_CurrentVersionRun_c0c8 {
  strings:
    $key_c0c8 = { 93 a7 [2] b7 a9 [2] 9c 85 [2] b2 a7 [2] a6 bc [2] a9 a6 [2] b7 bb [2] b5 ba [2] ae bc [2] b2 bb [2] ae 94 }

  condition:
    any of them
}