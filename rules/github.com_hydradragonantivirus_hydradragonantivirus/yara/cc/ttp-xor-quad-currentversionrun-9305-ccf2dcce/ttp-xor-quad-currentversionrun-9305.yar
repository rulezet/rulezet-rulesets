rule TTP_XOR_QUAD_CurrentVersionRun_9305 {
  strings:
    $key_9305 = { c0 6a [2] e4 64 [2] cf 48 [2] e1 6a [2] f5 71 [2] fa 6b [2] e4 76 [2] e6 77 [2] fd 71 [2] e1 76 [2] fd 59 }

  condition:
    any of them
}