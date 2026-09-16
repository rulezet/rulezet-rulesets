rule TTP_XOR_QUAD_CurrentVersionRun_93ea {
  strings:
    $key_93ea = { c0 85 [2] e4 8b [2] cf a7 [2] e1 85 [2] f5 9e [2] fa 84 [2] e4 99 [2] e6 98 [2] fd 9e [2] e1 99 [2] fd b6 }

  condition:
    any of them
}