rule TTP_XOR_QUAD_CurrentVersionRun_be87 {
  strings:
    $key_be87 = { ed e8 [2] c9 e6 [2] e2 ca [2] cc e8 [2] d8 f3 [2] d7 e9 [2] c9 f4 [2] cb f5 [2] d0 f3 [2] cc f4 [2] d0 db }

  condition:
    any of them
}