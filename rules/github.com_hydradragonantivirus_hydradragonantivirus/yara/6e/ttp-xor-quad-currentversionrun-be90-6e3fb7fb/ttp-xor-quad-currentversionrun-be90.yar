rule TTP_XOR_QUAD_CurrentVersionRun_be90 {
  strings:
    $key_be90 = { ed ff [2] c9 f1 [2] e2 dd [2] cc ff [2] d8 e4 [2] d7 fe [2] c9 e3 [2] cb e2 [2] d0 e4 [2] cc e3 [2] d0 cc }

  condition:
    any of them
}