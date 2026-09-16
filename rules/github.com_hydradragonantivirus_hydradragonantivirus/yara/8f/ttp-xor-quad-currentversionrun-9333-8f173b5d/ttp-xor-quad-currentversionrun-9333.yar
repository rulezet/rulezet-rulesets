rule TTP_XOR_QUAD_CurrentVersionRun_9333 {
  strings:
    $key_9333 = { c0 5c [2] e4 52 [2] cf 7e [2] e1 5c [2] f5 47 [2] fa 5d [2] e4 40 [2] e6 41 [2] fd 47 [2] e1 40 [2] fd 6f }

  condition:
    any of them
}