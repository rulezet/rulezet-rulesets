rule TTP_XOR_QUAD_CurrentVersionRun_9334 {
  strings:
    $key_9334 = { c0 5b [2] e4 55 [2] cf 79 [2] e1 5b [2] f5 40 [2] fa 5a [2] e4 47 [2] e6 46 [2] fd 40 [2] e1 47 [2] fd 68 }

  condition:
    any of them
}