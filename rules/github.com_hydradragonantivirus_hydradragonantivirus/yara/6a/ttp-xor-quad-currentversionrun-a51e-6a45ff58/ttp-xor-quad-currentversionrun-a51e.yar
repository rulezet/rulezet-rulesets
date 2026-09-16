rule TTP_XOR_QUAD_CurrentVersionRun_a51e {
  strings:
    $key_a51e = { f6 71 [2] d2 7f [2] f9 53 [2] d7 71 [2] c3 6a [2] cc 70 [2] d2 6d [2] d0 6c [2] cb 6a [2] d7 6d [2] cb 42 }

  condition:
    any of them
}