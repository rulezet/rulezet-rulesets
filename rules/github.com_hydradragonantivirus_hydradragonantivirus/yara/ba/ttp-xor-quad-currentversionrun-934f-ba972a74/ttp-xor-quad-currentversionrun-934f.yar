rule TTP_XOR_QUAD_CurrentVersionRun_934f {
  strings:
    $key_934f = { c0 20 [2] e4 2e [2] cf 02 [2] e1 20 [2] f5 3b [2] fa 21 [2] e4 3c [2] e6 3d [2] fd 3b [2] e1 3c [2] fd 13 }

  condition:
    any of them
}