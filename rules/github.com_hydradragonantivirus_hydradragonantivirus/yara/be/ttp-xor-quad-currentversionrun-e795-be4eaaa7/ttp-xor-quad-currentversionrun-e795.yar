rule TTP_XOR_QUAD_CurrentVersionRun_e795 {
  strings:
    $key_e795 = { b4 fa [2] 90 f4 [2] bb d8 [2] 95 fa [2] 81 e1 [2] 8e fb [2] 90 e6 [2] 92 e7 [2] 89 e1 [2] 95 e6 [2] 89 c9 }

  condition:
    any of them
}