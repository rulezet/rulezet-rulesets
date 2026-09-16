rule TTP_XOR_QUAD_CurrentVersionRun_93f9 {
  strings:
    $key_93f9 = { c0 96 [2] e4 98 [2] cf b4 [2] e1 96 [2] f5 8d [2] fa 97 [2] e4 8a [2] e6 8b [2] fd 8d [2] e1 8a [2] fd a5 }

  condition:
    any of them
}