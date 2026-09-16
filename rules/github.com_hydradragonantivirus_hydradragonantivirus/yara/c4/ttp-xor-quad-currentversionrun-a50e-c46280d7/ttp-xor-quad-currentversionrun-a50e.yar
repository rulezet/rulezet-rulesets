rule TTP_XOR_QUAD_CurrentVersionRun_a50e {
  strings:
    $key_a50e = { f6 61 [2] d2 6f [2] f9 43 [2] d7 61 [2] c3 7a [2] cc 60 [2] d2 7d [2] d0 7c [2] cb 7a [2] d7 7d [2] cb 52 }

  condition:
    any of them
}