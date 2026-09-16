rule TTP_XOR_QUAD_CurrentVersionRun_be80 {
  strings:
    $key_be80 = { ed ef [2] c9 e1 [2] e2 cd [2] cc ef [2] d8 f4 [2] d7 ee [2] c9 f3 [2] cb f2 [2] d0 f4 [2] cc f3 [2] d0 dc }

  condition:
    any of them
}