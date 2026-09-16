rule TTP_XOR_QUAD_CurrentVersionRun_9328 {
  strings:
    $key_9328 = { c0 47 [2] e4 49 [2] cf 65 [2] e1 47 [2] f5 5c [2] fa 46 [2] e4 5b [2] e6 5a [2] fd 5c [2] e1 5b [2] fd 74 }

  condition:
    any of them
}