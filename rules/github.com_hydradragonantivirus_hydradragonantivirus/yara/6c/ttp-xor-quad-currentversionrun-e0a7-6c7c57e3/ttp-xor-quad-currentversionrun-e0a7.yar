rule TTP_XOR_QUAD_CurrentVersionRun_e0a7 {
  strings:
    $key_e0a7 = { b3 c8 [2] 97 c6 [2] bc ea [2] 92 c8 [2] 86 d3 [2] 89 c9 [2] 97 d4 [2] 95 d5 [2] 8e d3 [2] 92 d4 [2] 8e fb }

  condition:
    any of them
}