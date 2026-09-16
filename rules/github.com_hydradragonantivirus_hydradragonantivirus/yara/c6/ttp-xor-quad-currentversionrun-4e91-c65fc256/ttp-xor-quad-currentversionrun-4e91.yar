rule TTP_XOR_QUAD_CurrentVersionRun_4e91 {
  strings:
    $key_4e91 = { 1d fe [2] 39 f0 [2] 12 dc [2] 3c fe [2] 28 e5 [2] 27 ff [2] 39 e2 [2] 3b e3 [2] 20 e5 [2] 3c e2 [2] 20 cd }

  condition:
    any of them
}