rule TTP_XOR_QUAD_CurrentVersionRun_93fa {
  strings:
    $key_93fa = { c0 95 [2] e4 9b [2] cf b7 [2] e1 95 [2] f5 8e [2] fa 94 [2] e4 89 [2] e6 88 [2] fd 8e [2] e1 89 [2] fd a6 }

  condition:
    any of them
}