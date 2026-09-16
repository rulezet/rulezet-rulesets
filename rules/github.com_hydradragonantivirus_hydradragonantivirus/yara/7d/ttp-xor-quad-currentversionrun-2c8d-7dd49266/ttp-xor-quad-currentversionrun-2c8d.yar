rule TTP_XOR_QUAD_CurrentVersionRun_2c8d {
  strings:
    $key_2c8d = { 7f e2 [2] 5b ec [2] 70 c0 [2] 5e e2 [2] 4a f9 [2] 45 e3 [2] 5b fe [2] 59 ff [2] 42 f9 [2] 5e fe [2] 42 d1 }

  condition:
    any of them
}