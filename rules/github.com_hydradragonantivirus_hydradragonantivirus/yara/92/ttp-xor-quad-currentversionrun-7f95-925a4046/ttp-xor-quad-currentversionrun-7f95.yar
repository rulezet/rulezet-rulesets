rule TTP_XOR_QUAD_CurrentVersionRun_7f95 {
  strings:
    $key_7f95 = { 2c fa [2] 08 f4 [2] 23 d8 [2] 0d fa [2] 19 e1 [2] 16 fb [2] 08 e6 [2] 0a e7 [2] 11 e1 [2] 0d e6 [2] 11 c9 }

  condition:
    any of them
}