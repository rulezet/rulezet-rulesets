rule TTP_XOR_QUAD_CurrentVersionRun_a517 {
  strings:
    $key_a517 = { f6 78 [2] d2 76 [2] f9 5a [2] d7 78 [2] c3 63 [2] cc 79 [2] d2 64 [2] d0 65 [2] cb 63 [2] d7 64 [2] cb 4b }

  condition:
    any of them
}