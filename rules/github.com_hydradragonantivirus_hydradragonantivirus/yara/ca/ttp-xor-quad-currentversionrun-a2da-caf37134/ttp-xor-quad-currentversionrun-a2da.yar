rule TTP_XOR_QUAD_CurrentVersionRun_a2da {
  strings:
    $key_a2da = { f1 b5 [2] d5 bb [2] fe 97 [2] d0 b5 [2] c4 ae [2] cb b4 [2] d5 a9 [2] d7 a8 [2] cc ae [2] d0 a9 [2] cc 86 }

  condition:
    any of them
}