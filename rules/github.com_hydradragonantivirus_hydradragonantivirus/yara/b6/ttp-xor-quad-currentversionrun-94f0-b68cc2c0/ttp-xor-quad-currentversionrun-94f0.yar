rule TTP_XOR_QUAD_CurrentVersionRun_94f0 {
  strings:
    $key_94f0 = { c7 9f [2] e3 91 [2] c8 bd [2] e6 9f [2] f2 84 [2] fd 9e [2] e3 83 [2] e1 82 [2] fa 84 [2] e6 83 [2] fa ac }

  condition:
    any of them
}