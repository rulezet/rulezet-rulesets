rule TTP_XOR_QUAD_CurrentVersionRun_931a {
  strings:
    $key_931a = { c0 75 [2] e4 7b [2] cf 57 [2] e1 75 [2] f5 6e [2] fa 74 [2] e4 69 [2] e6 68 [2] fd 6e [2] e1 69 [2] fd 46 }

  condition:
    any of them
}