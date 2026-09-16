rule TTP_XOR_QUAD_CurrentVersionRun_9379 {
  strings:
    $key_9379 = { c0 16 [2] e4 18 [2] cf 34 [2] e1 16 [2] f5 0d [2] fa 17 [2] e4 0a [2] e6 0b [2] fd 0d [2] e1 0a [2] fd 25 }

  condition:
    any of them
}