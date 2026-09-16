rule TTP_XOR_QUAD_CurrentVersionRun_a26c {
  strings:
    $key_a26c = { f1 03 [2] d5 0d [2] fe 21 [2] d0 03 [2] c4 18 [2] cb 02 [2] d5 1f [2] d7 1e [2] cc 18 [2] d0 1f [2] cc 30 }

  condition:
    any of them
}