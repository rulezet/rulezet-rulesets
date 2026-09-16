rule TTP_XOR_QUAD_CurrentVersionRun_12c8 {
  strings:
    $key_12c8 = { 41 a7 [2] 65 a9 [2] 4e 85 [2] 60 a7 [2] 74 bc [2] 7b a6 [2] 65 bb [2] 67 ba [2] 7c bc [2] 60 bb [2] 7c 94 }

  condition:
    any of them
}