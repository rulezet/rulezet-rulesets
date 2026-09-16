rule TTP_XOR_QUAD_CurrentVersionRun_e0d5 {
  strings:
    $key_e0d5 = { b3 ba [2] 97 b4 [2] bc 98 [2] 92 ba [2] 86 a1 [2] 89 bb [2] 97 a6 [2] 95 a7 [2] 8e a1 [2] 92 a6 [2] 8e 89 }

  condition:
    any of them
}