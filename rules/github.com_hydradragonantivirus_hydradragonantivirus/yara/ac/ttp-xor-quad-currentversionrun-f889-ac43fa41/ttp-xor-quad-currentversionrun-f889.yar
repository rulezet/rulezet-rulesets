rule TTP_XOR_QUAD_CurrentVersionRun_f889 {
  strings:
    $key_f889 = { ab e6 [2] 8f e8 [2] a4 c4 [2] 8a e6 [2] 9e fd [2] 91 e7 [2] 8f fa [2] 8d fb [2] 96 fd [2] 8a fa [2] 96 d5 }

  condition:
    any of them
}