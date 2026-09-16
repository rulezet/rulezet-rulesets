rule TTP_XOR_QUAD_CurrentVersionRun_5d8d {
  strings:
    $key_5d8d = { 0e e2 [2] 2a ec [2] 01 c0 [2] 2f e2 [2] 3b f9 [2] 34 e3 [2] 2a fe [2] 28 ff [2] 33 f9 [2] 2f fe [2] 33 d1 }

  condition:
    any of them
}