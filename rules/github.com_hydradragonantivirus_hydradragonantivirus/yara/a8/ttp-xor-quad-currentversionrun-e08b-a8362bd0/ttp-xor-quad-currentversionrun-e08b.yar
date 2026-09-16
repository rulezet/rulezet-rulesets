rule TTP_XOR_QUAD_CurrentVersionRun_e08b {
  strings:
    $key_e08b = { b3 e4 [2] 97 ea [2] bc c6 [2] 92 e4 [2] 86 ff [2] 89 e5 [2] 97 f8 [2] 95 f9 [2] 8e ff [2] 92 f8 [2] 8e d7 }

  condition:
    any of them
}