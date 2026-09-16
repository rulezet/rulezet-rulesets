rule TTP_XOR_QUAD_CurrentVersionRun_9308 {
  strings:
    $key_9308 = { c0 67 [2] e4 69 [2] cf 45 [2] e1 67 [2] f5 7c [2] fa 66 [2] e4 7b [2] e6 7a [2] fd 7c [2] e1 7b [2] fd 54 }

  condition:
    any of them
}