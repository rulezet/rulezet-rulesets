rule TTP_XOR_QUAD_CurrentVersionRun_9337 {
  strings:
    $key_9337 = { c0 58 [2] e4 56 [2] cf 7a [2] e1 58 [2] f5 43 [2] fa 59 [2] e4 44 [2] e6 45 [2] fd 43 [2] e1 44 [2] fd 6b }

  condition:
    any of them
}