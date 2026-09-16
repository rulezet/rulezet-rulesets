rule TTP_XOR_QUAD_CurrentVersionRun_3c8d {
  strings:
    $key_3c8d = { 6f e2 [2] 4b ec [2] 60 c0 [2] 4e e2 [2] 5a f9 [2] 55 e3 [2] 4b fe [2] 49 ff [2] 52 f9 [2] 4e fe [2] 52 d1 }

  condition:
    any of them
}