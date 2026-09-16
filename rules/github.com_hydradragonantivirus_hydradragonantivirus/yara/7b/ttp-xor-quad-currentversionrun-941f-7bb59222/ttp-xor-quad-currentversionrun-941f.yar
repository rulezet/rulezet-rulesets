rule TTP_XOR_QUAD_CurrentVersionRun_941f {
  strings:
    $key_941f = { c7 70 [2] e3 7e [2] c8 52 [2] e6 70 [2] f2 6b [2] fd 71 [2] e3 6c [2] e1 6d [2] fa 6b [2] e6 6c [2] fa 43 }

  condition:
    any of them
}