rule TTP_XOR_QUAD_CurrentVersionRun_fac8 {
  strings:
    $key_fac8 = { a9 a7 [2] 8d a9 [2] a6 85 [2] 88 a7 [2] 9c bc [2] 93 a6 [2] 8d bb [2] 8f ba [2] 94 bc [2] 88 bb [2] 94 94 }

  condition:
    any of them
}