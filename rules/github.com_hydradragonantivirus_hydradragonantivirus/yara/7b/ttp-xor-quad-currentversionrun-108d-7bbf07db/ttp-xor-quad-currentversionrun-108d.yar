rule TTP_XOR_QUAD_CurrentVersionRun_108d {
  strings:
    $key_108d = { 43 e2 [2] 67 ec [2] 4c c0 [2] 62 e2 [2] 76 f9 [2] 79 e3 [2] 67 fe [2] 65 ff [2] 7e f9 [2] 62 fe [2] 7e d1 }

  condition:
    any of them
}