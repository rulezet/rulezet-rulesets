rule TTP_XOR_QUAD_CurrentVersionRun_9425 {
  strings:
    $key_9425 = { c7 4a [2] e3 44 [2] c8 68 [2] e6 4a [2] f2 51 [2] fd 4b [2] e3 56 [2] e1 57 [2] fa 51 [2] e6 56 [2] fa 79 }

  condition:
    any of them
}