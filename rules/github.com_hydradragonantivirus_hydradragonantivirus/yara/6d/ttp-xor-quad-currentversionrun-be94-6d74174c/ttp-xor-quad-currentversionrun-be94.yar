rule TTP_XOR_QUAD_CurrentVersionRun_be94 {
  strings:
    $key_be94 = { ed fb [2] c9 f5 [2] e2 d9 [2] cc fb [2] d8 e0 [2] d7 fa [2] c9 e7 [2] cb e6 [2] d0 e0 [2] cc e7 [2] d0 c8 }

  condition:
    any of them
}