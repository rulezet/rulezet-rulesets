rule TTP_XOR_QUAD_CurrentVersionRun_93e8 {
  strings:
    $key_93e8 = { c0 87 [2] e4 89 [2] cf a5 [2] e1 87 [2] f5 9c [2] fa 86 [2] e4 9b [2] e6 9a [2] fd 9c [2] e1 9b [2] fd b4 }

  condition:
    any of them
}