rule TTP_XOR_QUAD_CurrentVersionRun_94f8 {
  strings:
    $key_94f8 = { c7 97 [2] e3 99 [2] c8 b5 [2] e6 97 [2] f2 8c [2] fd 96 [2] e3 8b [2] e1 8a [2] fa 8c [2] e6 8b [2] fa a4 }

  condition:
    any of them
}