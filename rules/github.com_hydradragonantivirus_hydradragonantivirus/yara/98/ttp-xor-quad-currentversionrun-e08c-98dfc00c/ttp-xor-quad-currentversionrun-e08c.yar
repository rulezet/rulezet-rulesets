rule TTP_XOR_QUAD_CurrentVersionRun_e08c {
  strings:
    $key_e08c = { b3 e3 [2] 97 ed [2] bc c1 [2] 92 e3 [2] 86 f8 [2] 89 e2 [2] 97 ff [2] 95 fe [2] 8e f8 [2] 92 ff [2] 8e d0 }

  condition:
    any of them
}