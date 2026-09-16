rule TTP_XOR_QUAD_CurrentVersionRun_a20d {
  strings:
    $key_a20d = { f1 62 [2] d5 6c [2] fe 40 [2] d0 62 [2] c4 79 [2] cb 63 [2] d5 7e [2] d7 7f [2] cc 79 [2] d0 7e [2] cc 51 }

  condition:
    any of them
}