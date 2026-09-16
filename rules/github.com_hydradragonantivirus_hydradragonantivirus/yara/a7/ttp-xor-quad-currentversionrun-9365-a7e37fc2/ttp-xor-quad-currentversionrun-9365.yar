rule TTP_XOR_QUAD_CurrentVersionRun_9365 {
  strings:
    $key_9365 = { c0 0a [2] e4 04 [2] cf 28 [2] e1 0a [2] f5 11 [2] fa 0b [2] e4 16 [2] e6 17 [2] fd 11 [2] e1 16 [2] fd 39 }

  condition:
    any of them
}