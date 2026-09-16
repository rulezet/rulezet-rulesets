rule TTP_XOR_QUAD_CurrentVersionRun_9360 {
  strings:
    $key_9360 = { c0 0f [2] e4 01 [2] cf 2d [2] e1 0f [2] f5 14 [2] fa 0e [2] e4 13 [2] e6 12 [2] fd 14 [2] e1 13 [2] fd 3c }

  condition:
    any of them
}