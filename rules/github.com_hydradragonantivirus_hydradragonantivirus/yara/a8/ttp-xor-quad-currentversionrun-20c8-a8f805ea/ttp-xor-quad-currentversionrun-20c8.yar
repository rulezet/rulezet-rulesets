rule TTP_XOR_QUAD_CurrentVersionRun_20c8 {
  strings:
    $key_20c8 = { 73 a7 [2] 57 a9 [2] 7c 85 [2] 52 a7 [2] 46 bc [2] 49 a6 [2] 57 bb [2] 55 ba [2] 4e bc [2] 52 bb [2] 4e 94 }

  condition:
    any of them
}