rule TTP_XOR_QUAD_CurrentVersionRun_a526 {
  strings:
    $key_a526 = { f6 49 [2] d2 47 [2] f9 6b [2] d7 49 [2] c3 52 [2] cc 48 [2] d2 55 [2] d0 54 [2] cb 52 [2] d7 55 [2] cb 7a }

  condition:
    any of them
}