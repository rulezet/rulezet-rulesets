rule TTP_XOR_QUAD_CurrentVersionRun_1e91 {
  strings:
    $key_1e91 = { 4d fe [2] 69 f0 [2] 42 dc [2] 6c fe [2] 78 e5 [2] 77 ff [2] 69 e2 [2] 6b e3 [2] 70 e5 [2] 6c e2 [2] 70 cd }

  condition:
    any of them
}