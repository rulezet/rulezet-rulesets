rule TTP_XOR_QUAD_CurrentVersionRun_0f95 {
  strings:
    $key_0f95 = { 5c fa [2] 78 f4 [2] 53 d8 [2] 7d fa [2] 69 e1 [2] 66 fb [2] 78 e6 [2] 7a e7 [2] 61 e1 [2] 7d e6 [2] 61 c9 }

  condition:
    any of them
}