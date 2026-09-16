rule TTP_XOR_QUAD_CurrentVersionRun_a29d {
  strings:
    $key_a29d = { f1 f2 [2] d5 fc [2] fe d0 [2] d0 f2 [2] c4 e9 [2] cb f3 [2] d5 ee [2] d7 ef [2] cc e9 [2] d0 ee [2] cc c1 }

  condition:
    any of them
}