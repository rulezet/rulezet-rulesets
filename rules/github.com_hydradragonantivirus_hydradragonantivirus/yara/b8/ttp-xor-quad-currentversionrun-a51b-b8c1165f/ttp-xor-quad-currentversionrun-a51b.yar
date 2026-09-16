rule TTP_XOR_QUAD_CurrentVersionRun_a51b {
  strings:
    $key_a51b = { f6 74 [2] d2 7a [2] f9 56 [2] d7 74 [2] c3 6f [2] cc 75 [2] d2 68 [2] d0 69 [2] cb 6f [2] d7 68 [2] cb 47 }

  condition:
    any of them
}