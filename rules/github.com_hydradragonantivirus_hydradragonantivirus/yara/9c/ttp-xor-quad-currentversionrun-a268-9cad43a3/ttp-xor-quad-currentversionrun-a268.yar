rule TTP_XOR_QUAD_CurrentVersionRun_a268 {
  strings:
    $key_a268 = { f1 07 [2] d5 09 [2] fe 25 [2] d0 07 [2] c4 1c [2] cb 06 [2] d5 1b [2] d7 1a [2] cc 1c [2] d0 1b [2] cc 34 }

  condition:
    any of them
}