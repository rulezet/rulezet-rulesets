rule TTP_XOR_QUAD_CurrentVersionRun_94eb {
  strings:
    $key_94eb = { c7 84 [2] e3 8a [2] c8 a6 [2] e6 84 [2] f2 9f [2] fd 85 [2] e3 98 [2] e1 99 [2] fa 9f [2] e6 98 [2] fa b7 }

  condition:
    any of them
}