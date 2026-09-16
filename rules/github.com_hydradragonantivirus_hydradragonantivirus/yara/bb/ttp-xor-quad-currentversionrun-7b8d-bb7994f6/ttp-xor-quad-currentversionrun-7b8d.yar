rule TTP_XOR_QUAD_CurrentVersionRun_7b8d {
  strings:
    $key_7b8d = { 28 e2 [2] 0c ec [2] 27 c0 [2] 09 e2 [2] 1d f9 [2] 12 e3 [2] 0c fe [2] 0e ff [2] 15 f9 [2] 09 fe [2] 15 d1 }

  condition:
    any of them
}