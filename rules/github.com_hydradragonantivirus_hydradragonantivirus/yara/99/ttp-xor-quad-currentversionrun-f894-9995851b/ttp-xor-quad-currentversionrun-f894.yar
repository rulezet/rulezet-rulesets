rule TTP_XOR_QUAD_CurrentVersionRun_f894 {
  strings:
    $key_f894 = { ab fb [2] 8f f5 [2] a4 d9 [2] 8a fb [2] 9e e0 [2] 91 fa [2] 8f e7 [2] 8d e6 [2] 96 e0 [2] 8a e7 [2] 96 c8 }

  condition:
    any of them
}