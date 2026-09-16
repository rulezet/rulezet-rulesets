rule TTP_XOR_QUAD_CurrentVersionRun_5bb6 {
  strings:
    $key_5bb6 = { 08 d9 [2] 2c d7 [2] 07 fb [2] 29 d9 [2] 3d c2 [2] 32 d8 [2] 2c c5 [2] 2e c4 [2] 35 c2 [2] 29 c5 [2] 35 ea }

  condition:
    any of them
}