rule TTP_XOR_QUAD_CurrentVersionRun_a56b {
  strings:
    $key_a56b = { f6 04 [2] d2 0a [2] f9 26 [2] d7 04 [2] c3 1f [2] cc 05 [2] d2 18 [2] d0 19 [2] cb 1f [2] d7 18 [2] cb 37 }

  condition:
    any of them
}