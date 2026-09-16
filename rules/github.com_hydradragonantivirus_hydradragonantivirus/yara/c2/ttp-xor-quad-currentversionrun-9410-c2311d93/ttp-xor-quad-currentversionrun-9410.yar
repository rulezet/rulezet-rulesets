rule TTP_XOR_QUAD_CurrentVersionRun_9410 {
  strings:
    $key_9410 = { c7 7f [2] e3 71 [2] c8 5d [2] e6 7f [2] f2 64 [2] fd 7e [2] e3 63 [2] e1 62 [2] fa 64 [2] e6 63 [2] fa 4c }

  condition:
    any of them
}