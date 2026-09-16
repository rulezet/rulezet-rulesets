rule TTP_XOR_QUAD_CurrentVersionRun_e0d3 {
  strings:
    $key_e0d3 = { b3 bc [2] 97 b2 [2] bc 9e [2] 92 bc [2] 86 a7 [2] 89 bd [2] 97 a0 [2] 95 a1 [2] 8e a7 [2] 92 a0 [2] 8e 8f }

  condition:
    any of them
}