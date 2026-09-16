rule TTP_XOR_QUAD_CurrentVersionRun_9435 {
  strings:
    $key_9435 = { c7 5a [2] e3 54 [2] c8 78 [2] e6 5a [2] f2 41 [2] fd 5b [2] e3 46 [2] e1 47 [2] fa 41 [2] e6 46 [2] fa 69 }

  condition:
    any of them
}