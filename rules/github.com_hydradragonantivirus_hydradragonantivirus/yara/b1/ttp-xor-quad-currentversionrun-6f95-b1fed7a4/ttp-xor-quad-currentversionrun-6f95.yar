rule TTP_XOR_QUAD_CurrentVersionRun_6f95 {
  strings:
    $key_6f95 = { 3c fa [2] 18 f4 [2] 33 d8 [2] 1d fa [2] 09 e1 [2] 06 fb [2] 18 e6 [2] 1a e7 [2] 01 e1 [2] 1d e6 [2] 01 c9 }

  condition:
    any of them
}