rule TTP_XOR_QUAD_CurrentVersionRun_fa8d {
  strings:
    $key_fa8d = { a9 e2 [2] 8d ec [2] a6 c0 [2] 88 e2 [2] 9c f9 [2] 93 e3 [2] 8d fe [2] 8f ff [2] 94 f9 [2] 88 fe [2] 94 d1 }

  condition:
    any of them
}