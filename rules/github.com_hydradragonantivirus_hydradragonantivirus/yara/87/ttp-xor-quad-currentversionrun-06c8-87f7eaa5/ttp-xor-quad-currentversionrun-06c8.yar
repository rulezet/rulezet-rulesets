rule TTP_XOR_QUAD_CurrentVersionRun_06c8 {
  strings:
    $key_06c8 = { 55 a7 [2] 71 a9 [2] 5a 85 [2] 74 a7 [2] 60 bc [2] 6f a6 [2] 71 bb [2] 73 ba [2] 68 bc [2] 74 bb [2] 68 94 }

  condition:
    any of them
}