rule TTP_XOR_QUAD_CurrentVersionRun_30c8 {
  strings:
    $key_30c8 = { 63 a7 [2] 47 a9 [2] 6c 85 [2] 42 a7 [2] 56 bc [2] 59 a6 [2] 47 bb [2] 45 ba [2] 5e bc [2] 42 bb [2] 5e 94 }

  condition:
    any of them
}