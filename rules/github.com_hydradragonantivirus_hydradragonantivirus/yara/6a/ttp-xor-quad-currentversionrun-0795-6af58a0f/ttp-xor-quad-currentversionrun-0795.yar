rule TTP_XOR_QUAD_CurrentVersionRun_0795 {
  strings:
    $key_0795 = { 54 fa [2] 70 f4 [2] 5b d8 [2] 75 fa [2] 61 e1 [2] 6e fb [2] 70 e6 [2] 72 e7 [2] 69 e1 [2] 75 e6 [2] 69 c9 }

  condition:
    any of them
}