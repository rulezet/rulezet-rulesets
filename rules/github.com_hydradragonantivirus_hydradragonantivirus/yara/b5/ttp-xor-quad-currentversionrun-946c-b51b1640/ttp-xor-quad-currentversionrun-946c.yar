rule TTP_XOR_QUAD_CurrentVersionRun_946c {
  strings:
    $key_946c = { c7 03 [2] e3 0d [2] c8 21 [2] e6 03 [2] f2 18 [2] fd 02 [2] e3 1f [2] e1 1e [2] fa 18 [2] e6 1f [2] fa 30 }

  condition:
    any of them
}