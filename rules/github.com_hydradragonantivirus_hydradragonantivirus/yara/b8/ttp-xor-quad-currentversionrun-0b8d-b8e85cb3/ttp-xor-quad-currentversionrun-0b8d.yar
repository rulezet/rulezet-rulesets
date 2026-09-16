rule TTP_XOR_QUAD_CurrentVersionRun_0b8d {
  strings:
    $key_0b8d = { 58 e2 [2] 7c ec [2] 57 c0 [2] 79 e2 [2] 6d f9 [2] 62 e3 [2] 7c fe [2] 7e ff [2] 65 f9 [2] 79 fe [2] 65 d1 }

  condition:
    any of them
}