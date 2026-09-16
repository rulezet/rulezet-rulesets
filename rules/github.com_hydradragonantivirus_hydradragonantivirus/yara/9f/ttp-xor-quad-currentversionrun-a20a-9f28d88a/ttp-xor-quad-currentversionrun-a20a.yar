rule TTP_XOR_QUAD_CurrentVersionRun_a20a {
  strings:
    $key_a20a = { f1 65 [2] d5 6b [2] fe 47 [2] d0 65 [2] c4 7e [2] cb 64 [2] d5 79 [2] d7 78 [2] cc 7e [2] d0 79 [2] cc 56 }

  condition:
    any of them
}