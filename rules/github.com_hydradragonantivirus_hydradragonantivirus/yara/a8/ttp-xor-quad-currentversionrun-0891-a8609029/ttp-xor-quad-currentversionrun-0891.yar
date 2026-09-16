rule TTP_XOR_QUAD_CurrentVersionRun_0891 {
  strings:
    $key_0891 = { 5b fe [2] 7f f0 [2] 54 dc [2] 7a fe [2] 6e e5 [2] 61 ff [2] 7f e2 [2] 7d e3 [2] 66 e5 [2] 7a e2 [2] 66 cd }

  condition:
    any of them
}