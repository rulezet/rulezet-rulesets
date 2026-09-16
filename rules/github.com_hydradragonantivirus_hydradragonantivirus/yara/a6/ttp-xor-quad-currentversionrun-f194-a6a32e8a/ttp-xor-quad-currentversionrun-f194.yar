rule TTP_XOR_QUAD_CurrentVersionRun_f194 {
  strings:
    $key_f194 = { a2 fb [2] 86 f5 [2] ad d9 [2] 83 fb [2] 97 e0 [2] 98 fa [2] 86 e7 [2] 84 e6 [2] 9f e0 [2] 83 e7 [2] 9f c8 }

  condition:
    any of them
}