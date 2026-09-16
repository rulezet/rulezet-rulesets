rule TTP_XOR_QUAD_CurrentVersionRun_5d91 {
  strings:
    $key_5d91 = { 0e fe [2] 2a f0 [2] 01 dc [2] 2f fe [2] 3b e5 [2] 34 ff [2] 2a e2 [2] 28 e3 [2] 33 e5 [2] 2f e2 [2] 33 cd }

  condition:
    any of them
}