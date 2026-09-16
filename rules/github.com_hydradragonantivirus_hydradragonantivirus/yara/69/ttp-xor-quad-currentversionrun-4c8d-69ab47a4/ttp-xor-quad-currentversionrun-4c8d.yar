rule TTP_XOR_QUAD_CurrentVersionRun_4c8d {
  strings:
    $key_4c8d = { 1f e2 [2] 3b ec [2] 10 c0 [2] 3e e2 [2] 2a f9 [2] 25 e3 [2] 3b fe [2] 39 ff [2] 22 f9 [2] 3e fe [2] 22 d1 }

  condition:
    any of them
}