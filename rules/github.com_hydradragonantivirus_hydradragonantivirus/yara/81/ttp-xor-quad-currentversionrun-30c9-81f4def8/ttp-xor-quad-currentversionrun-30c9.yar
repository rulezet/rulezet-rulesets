rule TTP_XOR_QUAD_CurrentVersionRun_30c9 {
  strings:
    $key_30c9 = { 63 a6 [2] 47 a8 [2] 6c 84 [2] 42 a6 [2] 56 bd [2] 59 a7 [2] 47 ba [2] 45 bb [2] 5e bd [2] 42 ba [2] 5e 95 }

  condition:
    any of them
}