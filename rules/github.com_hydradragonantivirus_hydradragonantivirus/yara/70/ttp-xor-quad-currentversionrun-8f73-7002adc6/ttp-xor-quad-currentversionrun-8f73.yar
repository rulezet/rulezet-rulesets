rule TTP_XOR_QUAD_CurrentVersionRun_8f73 {
  strings:
    $key_8f73 = { dc 1c [2] f8 12 [2] d3 3e [2] fd 1c [2] e9 07 [2] e6 1d [2] f8 00 [2] fa 01 [2] e1 07 [2] fd 00 [2] e1 2f }

  condition:
    any of them
}