rule TTP_XOR_QUAD_CurrentVersionRun_94fd {
  strings:
    $key_94fd = { c7 92 [2] e3 9c [2] c8 b0 [2] e6 92 [2] f2 89 [2] fd 93 [2] e3 8e [2] e1 8f [2] fa 89 [2] e6 8e [2] fa a1 }

  condition:
    any of them
}