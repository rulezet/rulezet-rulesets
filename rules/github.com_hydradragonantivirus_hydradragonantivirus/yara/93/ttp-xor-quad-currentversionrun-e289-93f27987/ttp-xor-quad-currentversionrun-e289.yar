rule TTP_XOR_QUAD_CurrentVersionRun_e289 {
  strings:
    $key_e289 = { b1 e6 [2] 95 e8 [2] be c4 [2] 90 e6 [2] 84 fd [2] 8b e7 [2] 95 fa [2] 97 fb [2] 8c fd [2] 90 fa [2] 8c d5 }

  condition:
    any of them
}