rule TTP_XOR_QUAD_CurrentVersionRun_7c8d {
  strings:
    $key_7c8d = { 2f e2 [2] 0b ec [2] 20 c0 [2] 0e e2 [2] 1a f9 [2] 15 e3 [2] 0b fe [2] 09 ff [2] 12 f9 [2] 0e fe [2] 12 d1 }

  condition:
    any of them
}