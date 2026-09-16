rule TTP_XOR_QUAD_CurrentVersionRun_3c91 {
  strings:
    $key_3c91 = { 6f fe [2] 4b f0 [2] 60 dc [2] 4e fe [2] 5a e5 [2] 55 ff [2] 4b e2 [2] 49 e3 [2] 52 e5 [2] 4e e2 [2] 52 cd }

  condition:
    any of them
}