rule TTP_XOR_QUAD_CurrentVersionRun_208d {
  strings:
    $key_208d = { 73 e2 [2] 57 ec [2] 7c c0 [2] 52 e2 [2] 46 f9 [2] 49 e3 [2] 57 fe [2] 55 ff [2] 4e f9 [2] 52 fe [2] 4e d1 }

  condition:
    any of them
}