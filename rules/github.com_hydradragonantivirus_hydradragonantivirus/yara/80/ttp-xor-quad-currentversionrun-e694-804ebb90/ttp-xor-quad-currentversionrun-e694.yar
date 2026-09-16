rule TTP_XOR_QUAD_CurrentVersionRun_e694 {
  strings:
    $key_e694 = { b5 fb [2] 91 f5 [2] ba d9 [2] 94 fb [2] 80 e0 [2] 8f fa [2] 91 e7 [2] 93 e6 [2] 88 e0 [2] 94 e7 [2] 88 c8 }

  condition:
    any of them
}