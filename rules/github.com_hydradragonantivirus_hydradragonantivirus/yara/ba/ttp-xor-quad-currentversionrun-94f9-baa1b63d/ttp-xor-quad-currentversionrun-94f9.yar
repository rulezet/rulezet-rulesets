rule TTP_XOR_QUAD_CurrentVersionRun_94f9 {
  strings:
    $key_94f9 = { c7 96 [2] e3 98 [2] c8 b4 [2] e6 96 [2] f2 8d [2] fd 97 [2] e3 8a [2] e1 8b [2] fa 8d [2] e6 8a [2] fa a5 }

  condition:
    any of them
}