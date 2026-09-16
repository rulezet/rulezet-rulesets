rule TTP_XOR_QUAD_CurrentVersionRun_2b8d {
  strings:
    $key_2b8d = { 78 e2 [2] 5c ec [2] 77 c0 [2] 59 e2 [2] 4d f9 [2] 42 e3 [2] 5c fe [2] 5e ff [2] 45 f9 [2] 59 fe [2] 45 d1 }

  condition:
    any of them
}