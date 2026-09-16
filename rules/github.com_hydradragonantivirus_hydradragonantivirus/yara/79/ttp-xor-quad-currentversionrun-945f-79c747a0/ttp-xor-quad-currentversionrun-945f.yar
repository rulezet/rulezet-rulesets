rule TTP_XOR_QUAD_CurrentVersionRun_945f {
  strings:
    $key_945f = { c7 30 [2] e3 3e [2] c8 12 [2] e6 30 [2] f2 2b [2] fd 31 [2] e3 2c [2] e1 2d [2] fa 2b [2] e6 2c [2] fa 03 }

  condition:
    any of them
}