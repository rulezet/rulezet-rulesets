rule TTP_XOR_QUAD_CurrentVersionRun_945a {
  strings:
    $key_945a = { c7 35 [2] e3 3b [2] c8 17 [2] e6 35 [2] f2 2e [2] fd 34 [2] e3 29 [2] e1 28 [2] fa 2e [2] e6 29 [2] fa 06 }

  condition:
    any of them
}