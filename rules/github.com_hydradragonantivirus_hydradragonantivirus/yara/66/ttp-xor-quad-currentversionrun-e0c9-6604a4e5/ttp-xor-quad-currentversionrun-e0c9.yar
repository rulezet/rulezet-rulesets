rule TTP_XOR_QUAD_CurrentVersionRun_e0c9 {
  strings:
    $key_e0c9 = { b3 a6 [2] 97 a8 [2] bc 84 [2] 92 a6 [2] 86 bd [2] 89 a7 [2] 97 ba [2] 95 bb [2] 8e bd [2] 92 ba [2] 8e 95 }

  condition:
    any of them
}