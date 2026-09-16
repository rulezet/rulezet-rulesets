rule TTP_XOR_QUAD_CurrentVersionRun_6d91 {
  strings:
    $key_6d91 = { 3e fe [2] 1a f0 [2] 31 dc [2] 1f fe [2] 0b e5 [2] 04 ff [2] 1a e2 [2] 18 e3 [2] 03 e5 [2] 1f e2 [2] 03 cd }

  condition:
    any of them
}