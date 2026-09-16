rule TTP_XOR_QUAD_CurrentVersionRun_4d8d {
  strings:
    $key_4d8d = { 1e e2 [2] 3a ec [2] 11 c0 [2] 3f e2 [2] 2b f9 [2] 24 e3 [2] 3a fe [2] 38 ff [2] 23 f9 [2] 3f fe [2] 23 d1 }

  condition:
    any of them
}