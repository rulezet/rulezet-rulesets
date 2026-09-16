rule TTP_XOR_QUAD_CurrentVersionRun_9318 {
  strings:
    $key_9318 = { c0 77 [2] e4 79 [2] cf 55 [2] e1 77 [2] f5 6c [2] fa 76 [2] e4 6b [2] e6 6a [2] fd 6c [2] e1 6b [2] fd 44 }

  condition:
    any of them
}