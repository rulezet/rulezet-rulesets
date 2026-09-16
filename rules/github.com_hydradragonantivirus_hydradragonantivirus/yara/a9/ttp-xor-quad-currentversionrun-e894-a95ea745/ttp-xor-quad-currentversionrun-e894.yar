rule TTP_XOR_QUAD_CurrentVersionRun_e894 {
  strings:
    $key_e894 = { bb fb [2] 9f f5 [2] b4 d9 [2] 9a fb [2] 8e e0 [2] 81 fa [2] 9f e7 [2] 9d e6 [2] 86 e0 [2] 9a e7 [2] 86 c8 }

  condition:
    any of them
}