rule TTP_XOR_QUAD_CurrentVersionRun_e594 {
  strings:
    $key_e594 = { b6 fb [2] 92 f5 [2] b9 d9 [2] 97 fb [2] 83 e0 [2] 8c fa [2] 92 e7 [2] 90 e6 [2] 8b e0 [2] 97 e7 [2] 8b c8 }

  condition:
    any of them
}