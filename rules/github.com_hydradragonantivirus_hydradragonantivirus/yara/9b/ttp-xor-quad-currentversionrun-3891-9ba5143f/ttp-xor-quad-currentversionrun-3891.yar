rule TTP_XOR_QUAD_CurrentVersionRun_3891 {
  strings:
    $key_3891 = { 6b fe [2] 4f f0 [2] 64 dc [2] 4a fe [2] 5e e5 [2] 51 ff [2] 4f e2 [2] 4d e3 [2] 56 e5 [2] 4a e2 [2] 56 cd }

  condition:
    any of them
}