rule TTP_XOR_QUAD_CurrentVersionRun_93ef {
  strings:
    $key_93ef = { c0 80 [2] e4 8e [2] cf a2 [2] e1 80 [2] f5 9b [2] fa 81 [2] e4 9c [2] e6 9d [2] fd 9b [2] e1 9c [2] fd b3 }

  condition:
    any of them
}