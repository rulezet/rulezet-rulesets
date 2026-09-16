rule TTP_XOR_QUAD_CurrentVersionRun_5e91 {
  strings:
    $key_5e91 = { 0d fe [2] 29 f0 [2] 02 dc [2] 2c fe [2] 38 e5 [2] 37 ff [2] 29 e2 [2] 2b e3 [2] 30 e5 [2] 2c e2 [2] 30 cd }

  condition:
    any of them
}