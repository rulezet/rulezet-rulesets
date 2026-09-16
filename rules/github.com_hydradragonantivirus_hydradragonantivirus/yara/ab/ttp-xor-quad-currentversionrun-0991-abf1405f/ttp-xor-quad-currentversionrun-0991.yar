rule TTP_XOR_QUAD_CurrentVersionRun_0991 {
  strings:
    $key_0991 = { 5a fe [2] 7e f0 [2] 55 dc [2] 7b fe [2] 6f e5 [2] 60 ff [2] 7e e2 [2] 7c e3 [2] 67 e5 [2] 7b e2 [2] 67 cd }

  condition:
    any of them
}