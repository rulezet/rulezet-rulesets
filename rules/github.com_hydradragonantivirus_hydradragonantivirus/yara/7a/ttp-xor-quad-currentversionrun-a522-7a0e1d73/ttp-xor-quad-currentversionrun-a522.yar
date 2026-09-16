rule TTP_XOR_QUAD_CurrentVersionRun_a522 {
  strings:
    $key_a522 = { f6 4d [2] d2 43 [2] f9 6f [2] d7 4d [2] c3 56 [2] cc 4c [2] d2 51 [2] d0 50 [2] cb 56 [2] d7 51 [2] cb 7e }

  condition:
    any of them
}