rule TTP_XOR_QUAD_CurrentVersionRun_be9b {
  strings:
    $key_be9b = { ed f4 [2] c9 fa [2] e2 d6 [2] cc f4 [2] d8 ef [2] d7 f5 [2] c9 e8 [2] cb e9 [2] d0 ef [2] cc e8 [2] d0 c7 }

  condition:
    any of them
}