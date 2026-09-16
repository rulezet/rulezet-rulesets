rule TTP_XOR_QUAD_CurrentVersionRun_6c8d {
  strings:
    $key_6c8d = { 3f e2 [2] 1b ec [2] 30 c0 [2] 1e e2 [2] 0a f9 [2] 05 e3 [2] 1b fe [2] 19 ff [2] 02 f9 [2] 1e fe [2] 02 d1 }

  condition:
    any of them
}