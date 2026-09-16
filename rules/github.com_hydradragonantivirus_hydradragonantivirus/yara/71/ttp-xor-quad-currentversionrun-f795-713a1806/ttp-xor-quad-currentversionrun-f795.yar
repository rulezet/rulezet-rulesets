rule TTP_XOR_QUAD_CurrentVersionRun_f795 {
  strings:
    $key_f795 = { a4 fa [2] 80 f4 [2] ab d8 [2] 85 fa [2] 91 e1 [2] 9e fb [2] 80 e6 [2] 82 e7 [2] 99 e1 [2] 85 e6 [2] 99 c9 }

  condition:
    any of them
}