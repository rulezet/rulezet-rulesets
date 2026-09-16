rule TTP_XOR_QUAD_CurrentVersionRun_7c91 {
  strings:
    $key_7c91 = { 2f fe [2] 0b f0 [2] 20 dc [2] 0e fe [2] 1a e5 [2] 15 ff [2] 0b e2 [2] 09 e3 [2] 12 e5 [2] 0e e2 [2] 12 cd }

  condition:
    any of them
}