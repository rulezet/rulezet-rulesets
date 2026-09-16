rule TTP_XOR_QUAD_CurrentVersionRun_9428 {
  strings:
    $key_9428 = { c7 47 [2] e3 49 [2] c8 65 [2] e6 47 [2] f2 5c [2] fd 46 [2] e3 5b [2] e1 5a [2] fa 5c [2] e6 5b [2] fa 74 }

  condition:
    any of them
}