rule TTP_XOR_QUAD_CurrentVersionRun_8f19 {
  strings:
    $key_8f19 = { dc 76 [2] f8 78 [2] d3 54 [2] fd 76 [2] e9 6d [2] e6 77 [2] f8 6a [2] fa 6b [2] e1 6d [2] fd 6a [2] e1 45 }

  condition:
    any of them
}