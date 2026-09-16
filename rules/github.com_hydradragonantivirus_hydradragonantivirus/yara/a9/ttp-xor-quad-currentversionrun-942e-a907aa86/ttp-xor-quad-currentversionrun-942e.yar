rule TTP_XOR_QUAD_CurrentVersionRun_942e {
  strings:
    $key_942e = { c7 41 [2] e3 4f [2] c8 63 [2] e6 41 [2] f2 5a [2] fd 40 [2] e3 5d [2] e1 5c [2] fa 5a [2] e6 5d [2] fa 72 }

  condition:
    any of them
}