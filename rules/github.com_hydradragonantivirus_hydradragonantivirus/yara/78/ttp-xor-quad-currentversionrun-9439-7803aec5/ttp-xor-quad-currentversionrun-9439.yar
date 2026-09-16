rule TTP_XOR_QUAD_CurrentVersionRun_9439 {
  strings:
    $key_9439 = { c7 56 [2] e3 58 [2] c8 74 [2] e6 56 [2] f2 4d [2] fd 57 [2] e3 4a [2] e1 4b [2] fa 4d [2] e6 4a [2] fa 65 }

  condition:
    any of them
}