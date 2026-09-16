rule TTP_XOR_QUAD_CurrentVersionRun_94e1 {
  strings:
    $key_94e1 = { c7 8e [2] e3 80 [2] c8 ac [2] e6 8e [2] f2 95 [2] fd 8f [2] e3 92 [2] e1 93 [2] fa 95 [2] e6 92 [2] fa bd }

  condition:
    any of them
}