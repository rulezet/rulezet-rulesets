rule TTP_XOR_QUAD_CurrentVersionRun_34c8 {
  strings:
    $key_34c8 = { 67 a7 [2] 43 a9 [2] 68 85 [2] 46 a7 [2] 52 bc [2] 5d a6 [2] 43 bb [2] 41 ba [2] 5a bc [2] 46 bb [2] 5a 94 }

  condition:
    any of them
}