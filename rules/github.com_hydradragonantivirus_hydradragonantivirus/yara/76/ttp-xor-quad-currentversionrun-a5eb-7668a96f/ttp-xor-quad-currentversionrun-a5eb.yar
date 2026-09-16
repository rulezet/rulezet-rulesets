rule TTP_XOR_QUAD_CurrentVersionRun_a5eb {
  strings:
    $key_a5eb = { f6 84 [2] d2 8a [2] f9 a6 [2] d7 84 [2] c3 9f [2] cc 85 [2] d2 98 [2] d0 99 [2] cb 9f [2] d7 98 [2] cb b7 }

  condition:
    any of them
}