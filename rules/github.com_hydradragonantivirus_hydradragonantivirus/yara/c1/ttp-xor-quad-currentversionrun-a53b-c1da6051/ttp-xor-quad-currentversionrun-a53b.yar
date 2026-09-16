rule TTP_XOR_QUAD_CurrentVersionRun_a53b {
  strings:
    $key_a53b = { f6 54 [2] d2 5a [2] f9 76 [2] d7 54 [2] c3 4f [2] cc 55 [2] d2 48 [2] d0 49 [2] cb 4f [2] d7 48 [2] cb 67 }

  condition:
    any of them
}