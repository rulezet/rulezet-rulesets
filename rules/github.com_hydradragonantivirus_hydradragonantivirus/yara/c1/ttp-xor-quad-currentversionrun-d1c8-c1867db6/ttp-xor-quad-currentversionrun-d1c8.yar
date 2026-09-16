rule TTP_XOR_QUAD_CurrentVersionRun_d1c8 {
  strings:
    $key_d1c8 = { 82 a7 [2] a6 a9 [2] 8d 85 [2] a3 a7 [2] b7 bc [2] b8 a6 [2] a6 bb [2] a4 ba [2] bf bc [2] a3 bb [2] bf 94 }

  condition:
    any of them
}