rule TTP_XOR_QUAD_CurrentVersionRun_a23d {
  strings:
    $key_a23d = { f1 52 [2] d5 5c [2] fe 70 [2] d0 52 [2] c4 49 [2] cb 53 [2] d5 4e [2] d7 4f [2] cc 49 [2] d0 4e [2] cc 61 }

  condition:
    any of them
}