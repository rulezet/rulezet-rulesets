rule TTP_XOR_QUAD_CurrentVersionRun_a21e {
  strings:
    $key_a21e = { f1 71 [2] d5 7f [2] fe 53 [2] d0 71 [2] c4 6a [2] cb 70 [2] d5 6d [2] d7 6c [2] cc 6a [2] d0 6d [2] cc 42 }

  condition:
    any of them
}