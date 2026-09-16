rule TTP_XOR_QUAD_CurrentVersionRun_e0c8 {
  strings:
    $key_e0c8 = { b3 a7 [2] 97 a9 [2] bc 85 [2] 92 a7 [2] 86 bc [2] 89 a6 [2] 97 bb [2] 95 ba [2] 8e bc [2] 92 bb [2] 8e 94 }

  condition:
    any of them
}