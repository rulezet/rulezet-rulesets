rule TTP_XOR_QUAD_CurrentVersionRun_0fa8 {
  strings:
    $key_0fa8 = { 5c c7 [2] 78 c9 [2] 53 e5 [2] 7d c7 [2] 69 dc [2] 66 c6 [2] 78 db [2] 7a da [2] 61 dc [2] 7d db [2] 61 f4 }

  condition:
    any of them
}