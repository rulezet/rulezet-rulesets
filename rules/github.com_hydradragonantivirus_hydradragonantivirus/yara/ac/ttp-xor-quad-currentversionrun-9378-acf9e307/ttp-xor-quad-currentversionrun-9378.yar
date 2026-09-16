rule TTP_XOR_QUAD_CurrentVersionRun_9378 {
  strings:
    $key_9378 = { c0 17 [2] e4 19 [2] cf 35 [2] e1 17 [2] f5 0c [2] fa 16 [2] e4 0b [2] e6 0a [2] fd 0c [2] e1 0b [2] fd 24 }

  condition:
    any of them
}