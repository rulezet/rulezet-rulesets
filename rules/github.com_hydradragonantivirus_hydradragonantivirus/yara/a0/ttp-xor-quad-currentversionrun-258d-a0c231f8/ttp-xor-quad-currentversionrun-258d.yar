rule TTP_XOR_QUAD_CurrentVersionRun_258d {
  strings:
    $key_258d = { 76 e2 [2] 52 ec [2] 79 c0 [2] 57 e2 [2] 43 f9 [2] 4c e3 [2] 52 fe [2] 50 ff [2] 4b f9 [2] 57 fe [2] 4b d1 }

  condition:
    any of them
}