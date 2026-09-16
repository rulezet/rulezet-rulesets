rule TTP_XOR_QUAD_CurrentVersionRun_9448 {
  strings:
    $key_9448 = { c7 27 [2] e3 29 [2] c8 05 [2] e6 27 [2] f2 3c [2] fd 26 [2] e3 3b [2] e1 3a [2] fa 3c [2] e6 3b [2] fa 14 }

  condition:
    any of them
}