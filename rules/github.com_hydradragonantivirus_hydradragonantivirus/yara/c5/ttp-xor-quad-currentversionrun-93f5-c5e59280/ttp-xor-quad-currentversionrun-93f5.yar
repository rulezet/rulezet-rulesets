rule TTP_XOR_QUAD_CurrentVersionRun_93f5 {
  strings:
    $key_93f5 = { c0 9a [2] e4 94 [2] cf b8 [2] e1 9a [2] f5 81 [2] fa 9b [2] e4 86 [2] e6 87 [2] fd 81 [2] e1 86 [2] fd a9 }

  condition:
    any of them
}