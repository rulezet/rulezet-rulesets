rule TTP_XOR_QUAD_CurrentVersionRun_9325 {
  strings:
    $key_9325 = { c0 4a [2] e4 44 [2] cf 68 [2] e1 4a [2] f5 51 [2] fa 4b [2] e4 56 [2] e6 57 [2] fd 51 [2] e1 56 [2] fd 79 }

  condition:
    any of them
}