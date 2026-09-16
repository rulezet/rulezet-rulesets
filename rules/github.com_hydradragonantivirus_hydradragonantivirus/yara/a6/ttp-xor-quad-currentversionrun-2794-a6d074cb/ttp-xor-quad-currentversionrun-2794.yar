rule TTP_XOR_QUAD_CurrentVersionRun_2794 {
  strings:
    $key_2794 = { 74 fb [2] 50 f5 [2] 7b d9 [2] 55 fb [2] 41 e0 [2] 4e fa [2] 50 e7 [2] 52 e6 [2] 49 e0 [2] 55 e7 [2] 49 c8 }

  condition:
    any of them
}