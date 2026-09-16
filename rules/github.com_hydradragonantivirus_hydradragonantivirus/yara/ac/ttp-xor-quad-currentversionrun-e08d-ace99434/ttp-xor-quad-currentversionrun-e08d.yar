rule TTP_XOR_QUAD_CurrentVersionRun_e08d {
  strings:
    $key_e08d = { b3 e2 [2] 97 ec [2] bc c0 [2] 92 e2 [2] 86 f9 [2] 89 e3 [2] 97 fe [2] 95 ff [2] 8e f9 [2] 92 fe [2] 8e d1 }

  condition:
    any of them
}