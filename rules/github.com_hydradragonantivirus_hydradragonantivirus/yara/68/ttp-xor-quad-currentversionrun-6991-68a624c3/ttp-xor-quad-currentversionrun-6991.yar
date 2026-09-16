rule TTP_XOR_QUAD_CurrentVersionRun_6991 {
  strings:
    $key_6991 = { 3a fe [2] 1e f0 [2] 35 dc [2] 1b fe [2] 0f e5 [2] 00 ff [2] 1e e2 [2] 1c e3 [2] 07 e5 [2] 1b e2 [2] 07 cd }

  condition:
    any of them
}