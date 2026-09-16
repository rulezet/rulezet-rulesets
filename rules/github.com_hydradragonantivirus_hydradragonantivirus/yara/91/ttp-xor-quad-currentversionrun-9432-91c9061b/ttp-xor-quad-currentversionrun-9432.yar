rule TTP_XOR_QUAD_CurrentVersionRun_9432 {
  strings:
    $key_9432 = { c7 5d [2] e3 53 [2] c8 7f [2] e6 5d [2] f2 46 [2] fd 5c [2] e3 41 [2] e1 40 [2] fa 46 [2] e6 41 [2] fa 6e }

  condition:
    any of them
}