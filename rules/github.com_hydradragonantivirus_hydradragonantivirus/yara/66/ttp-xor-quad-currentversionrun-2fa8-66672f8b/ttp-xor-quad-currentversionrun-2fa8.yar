rule TTP_XOR_QUAD_CurrentVersionRun_2fa8 {
  strings:
    $key_2fa8 = { 7c c7 [2] 58 c9 [2] 73 e5 [2] 5d c7 [2] 49 dc [2] 46 c6 [2] 58 db [2] 5a da [2] 41 dc [2] 5d db [2] 41 f4 }

  condition:
    any of them
}