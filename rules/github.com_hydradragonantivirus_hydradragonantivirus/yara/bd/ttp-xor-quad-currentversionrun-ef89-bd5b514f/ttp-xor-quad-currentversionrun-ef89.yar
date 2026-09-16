rule TTP_XOR_QUAD_CurrentVersionRun_ef89 {
  strings:
    $key_ef89 = { bc e6 [2] 98 e8 [2] b3 c4 [2] 9d e6 [2] 89 fd [2] 86 e7 [2] 98 fa [2] 9a fb [2] 81 fd [2] 9d fa [2] 81 d5 }

  condition:
    any of them
}