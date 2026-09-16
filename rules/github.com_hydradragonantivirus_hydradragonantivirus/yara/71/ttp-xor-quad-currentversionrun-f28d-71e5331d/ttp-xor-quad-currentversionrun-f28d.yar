rule TTP_XOR_QUAD_CurrentVersionRun_f28d {
  strings:
    $key_f28d = { a1 e2 [2] 85 ec [2] ae c0 [2] 80 e2 [2] 94 f9 [2] 9b e3 [2] 85 fe [2] 87 ff [2] 9c f9 [2] 80 fe [2] 9c d1 }

  condition:
    any of them
}