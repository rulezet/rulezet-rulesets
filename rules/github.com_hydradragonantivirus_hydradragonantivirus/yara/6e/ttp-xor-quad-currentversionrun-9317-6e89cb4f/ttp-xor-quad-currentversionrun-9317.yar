rule TTP_XOR_QUAD_CurrentVersionRun_9317 {
  strings:
    $key_9317 = { c0 78 [2] e4 76 [2] cf 5a [2] e1 78 [2] f5 63 [2] fa 79 [2] e4 64 [2] e6 65 [2] fd 63 [2] e1 64 [2] fd 4b }

  condition:
    any of them
}