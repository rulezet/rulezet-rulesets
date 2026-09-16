rule TTP_XOR_QUAD_CurrentVersionRun_fb8d {
  strings:
    $key_fb8d = { a8 e2 [2] 8c ec [2] a7 c0 [2] 89 e2 [2] 9d f9 [2] 92 e3 [2] 8c fe [2] 8e ff [2] 95 f9 [2] 89 fe [2] 95 d1 }

  condition:
    any of them
}