rule TTP_XOR_QUAD_CurrentVersionRun_940b {
  strings:
    $key_940b = { c7 64 [2] e3 6a [2] c8 46 [2] e6 64 [2] f2 7f [2] fd 65 [2] e3 78 [2] e1 79 [2] fa 7f [2] e6 78 [2] fa 57 }

  condition:
    any of them
}