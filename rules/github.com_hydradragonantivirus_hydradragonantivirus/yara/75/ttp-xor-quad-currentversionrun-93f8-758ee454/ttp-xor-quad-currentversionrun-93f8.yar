rule TTP_XOR_QUAD_CurrentVersionRun_93f8 {
  strings:
    $key_93f8 = { c0 97 [2] e4 99 [2] cf b5 [2] e1 97 [2] f5 8c [2] fa 96 [2] e4 8b [2] e6 8a [2] fd 8c [2] e1 8b [2] fd a4 }

  condition:
    any of them
}