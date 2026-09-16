rule TTP_XOR_QUAD_CurrentVersionRun_f195 {
  strings:
    $key_f195 = { a2 fa [2] 86 f4 [2] ad d8 [2] 83 fa [2] 97 e1 [2] 98 fb [2] 86 e6 [2] 84 e7 [2] 9f e1 [2] 83 e6 [2] 9f c9 }

  condition:
    any of them
}