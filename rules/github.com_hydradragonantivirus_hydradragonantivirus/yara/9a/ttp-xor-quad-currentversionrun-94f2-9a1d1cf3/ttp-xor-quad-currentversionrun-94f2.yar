rule TTP_XOR_QUAD_CurrentVersionRun_94f2 {
  strings:
    $key_94f2 = { c7 9d [2] e3 93 [2] c8 bf [2] e6 9d [2] f2 86 [2] fd 9c [2] e3 81 [2] e1 80 [2] fa 86 [2] e6 81 [2] fa ae }

  condition:
    any of them
}