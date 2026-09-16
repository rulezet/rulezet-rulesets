rule TTP_XOR_QUAD_CurrentVersionRun_946d {
  strings:
    $key_946d = { c7 02 [2] e3 0c [2] c8 20 [2] e6 02 [2] f2 19 [2] fd 03 [2] e3 1e [2] e1 1f [2] fa 19 [2] e6 1e [2] fa 31 }

  condition:
    any of them
}