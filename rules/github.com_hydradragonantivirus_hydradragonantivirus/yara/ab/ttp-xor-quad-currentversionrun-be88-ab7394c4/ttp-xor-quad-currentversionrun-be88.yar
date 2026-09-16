rule TTP_XOR_QUAD_CurrentVersionRun_be88 {
  strings:
    $key_be88 = { ed e7 [2] c9 e9 [2] e2 c5 [2] cc e7 [2] d8 fc [2] d7 e6 [2] c9 fb [2] cb fa [2] d0 fc [2] cc fb [2] d0 d4 }

  condition:
    any of them
}