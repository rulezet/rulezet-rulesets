rule TTP_XOR_QUAD_CurrentVersionRun_a52e {
  strings:
    $key_a52e = { f6 41 [2] d2 4f [2] f9 63 [2] d7 41 [2] c3 5a [2] cc 40 [2] d2 5d [2] d0 5c [2] cb 5a [2] d7 5d [2] cb 72 }

  condition:
    any of them
}