rule TTP_XOR_QUAD_CurrentVersionRun_9415 {
  strings:
    $key_9415 = { c7 7a [2] e3 74 [2] c8 58 [2] e6 7a [2] f2 61 [2] fd 7b [2] e3 66 [2] e1 67 [2] fa 61 [2] e6 66 [2] fa 49 }

  condition:
    any of them
}