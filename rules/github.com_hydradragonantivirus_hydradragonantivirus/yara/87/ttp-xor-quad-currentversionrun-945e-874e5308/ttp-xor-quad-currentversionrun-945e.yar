rule TTP_XOR_QUAD_CurrentVersionRun_945e {
  strings:
    $key_945e = { c7 31 [2] e3 3f [2] c8 13 [2] e6 31 [2] f2 2a [2] fd 30 [2] e3 2d [2] e1 2c [2] fa 2a [2] e6 2d [2] fa 02 }

  condition:
    any of them
}