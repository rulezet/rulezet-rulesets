rule TTP_XOR_QUAD_CurrentVersionRun_fc91 {
  strings:
    $key_fc91 = { af fe [2] 8b f0 [2] a0 dc [2] 8e fe [2] 9a e5 [2] 95 ff [2] 8b e2 [2] 89 e3 [2] 92 e5 [2] 8e e2 [2] 92 cd }

  condition:
    any of them
}