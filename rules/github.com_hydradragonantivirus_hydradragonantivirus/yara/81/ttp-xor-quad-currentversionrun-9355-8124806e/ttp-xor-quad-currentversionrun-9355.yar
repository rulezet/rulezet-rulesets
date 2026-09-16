rule TTP_XOR_QUAD_CurrentVersionRun_9355 {
  strings:
    $key_9355 = { c0 3a [2] e4 34 [2] cf 18 [2] e1 3a [2] f5 21 [2] fa 3b [2] e4 26 [2] e6 27 [2] fd 21 [2] e1 26 [2] fd 09 }

  condition:
    any of them
}