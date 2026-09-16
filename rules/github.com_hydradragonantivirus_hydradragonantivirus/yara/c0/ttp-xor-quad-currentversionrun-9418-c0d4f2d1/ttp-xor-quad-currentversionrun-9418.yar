rule TTP_XOR_QUAD_CurrentVersionRun_9418 {
  strings:
    $key_9418 = { c7 77 [2] e3 79 [2] c8 55 [2] e6 77 [2] f2 6c [2] fd 76 [2] e3 6b [2] e1 6a [2] fa 6c [2] e6 6b [2] fa 44 }

  condition:
    any of them
}