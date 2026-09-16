rule TTP_XOR_QUAD_CurrentVersionRun_a2dc {
  strings:
    $key_a2dc = { f1 b3 [2] d5 bd [2] fe 91 [2] d0 b3 [2] c4 a8 [2] cb b2 [2] d5 af [2] d7 ae [2] cc a8 [2] d0 af [2] cc 80 }

  condition:
    any of them
}