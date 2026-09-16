rule TTP_XOR_QUAD_CurrentVersionRun_7891 {
  strings:
    $key_7891 = { 2b fe [2] 0f f0 [2] 24 dc [2] 0a fe [2] 1e e5 [2] 11 ff [2] 0f e2 [2] 0d e3 [2] 16 e5 [2] 0a e2 [2] 16 cd }

  condition:
    any of them
}