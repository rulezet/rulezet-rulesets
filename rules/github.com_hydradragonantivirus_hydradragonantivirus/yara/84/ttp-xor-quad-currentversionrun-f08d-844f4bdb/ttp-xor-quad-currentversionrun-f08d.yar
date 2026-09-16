rule TTP_XOR_QUAD_CurrentVersionRun_f08d {
  strings:
    $key_f08d = { a3 e2 [2] 87 ec [2] ac c0 [2] 82 e2 [2] 96 f9 [2] 99 e3 [2] 87 fe [2] 85 ff [2] 9e f9 [2] 82 fe [2] 9e d1 }

  condition:
    any of them
}