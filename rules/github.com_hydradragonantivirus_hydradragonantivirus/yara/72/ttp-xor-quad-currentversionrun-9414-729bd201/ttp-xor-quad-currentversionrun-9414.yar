rule TTP_XOR_QUAD_CurrentVersionRun_9414 {
  strings:
    $key_9414 = { c7 7b [2] e3 75 [2] c8 59 [2] e6 7b [2] f2 60 [2] fd 7a [2] e3 67 [2] e1 66 [2] fa 60 [2] e6 67 [2] fa 48 }

  condition:
    any of them
}