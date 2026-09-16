rule TTP_XOR_QUAD_CurrentVersionRun_9433 {
  strings:
    $key_9433 = { c7 5c [2] e3 52 [2] c8 7e [2] e6 5c [2] f2 47 [2] fd 5d [2] e3 40 [2] e1 41 [2] fa 47 [2] e6 40 [2] fa 6f }

  condition:
    any of them
}