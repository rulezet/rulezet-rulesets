rule TTP_XOR_QUAD_CurrentVersionRun_9460 {
  strings:
    $key_9460 = { c7 0f [2] e3 01 [2] c8 2d [2] e6 0f [2] f2 14 [2] fd 0e [2] e3 13 [2] e1 12 [2] fa 14 [2] e6 13 [2] fa 3c }

  condition:
    any of them
}