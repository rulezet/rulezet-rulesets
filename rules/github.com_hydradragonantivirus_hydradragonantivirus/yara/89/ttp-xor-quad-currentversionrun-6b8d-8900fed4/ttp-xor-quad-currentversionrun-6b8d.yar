rule TTP_XOR_QUAD_CurrentVersionRun_6b8d {
  strings:
    $key_6b8d = { 38 e2 [2] 1c ec [2] 37 c0 [2] 19 e2 [2] 0d f9 [2] 02 e3 [2] 1c fe [2] 1e ff [2] 05 f9 [2] 19 fe [2] 05 d1 }

  condition:
    any of them
}