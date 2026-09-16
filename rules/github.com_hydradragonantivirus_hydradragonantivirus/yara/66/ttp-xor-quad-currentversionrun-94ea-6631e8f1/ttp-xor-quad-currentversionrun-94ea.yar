rule TTP_XOR_QUAD_CurrentVersionRun_94ea {
  strings:
    $key_94ea = { c7 85 [2] e3 8b [2] c8 a7 [2] e6 85 [2] f2 9e [2] fd 84 [2] e3 99 [2] e1 98 [2] fa 9e [2] e6 99 [2] fa b6 }

  condition:
    any of them
}