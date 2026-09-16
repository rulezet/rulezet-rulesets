rule TTP_XOR_QUAD_CurrentVersionRun_a532 {
  strings:
    $key_a532 = { f6 5d [2] d2 53 [2] f9 7f [2] d7 5d [2] c3 46 [2] cc 5c [2] d2 41 [2] d0 40 [2] cb 46 [2] d7 41 [2] cb 6e }

  condition:
    any of them
}