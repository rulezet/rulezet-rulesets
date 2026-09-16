rule TTP_XOR_QUAD_CurrentVersionRun_8f72 {
  strings:
    $key_8f72 = { dc 1d [2] f8 13 [2] d3 3f [2] fd 1d [2] e9 06 [2] e6 1c [2] f8 01 [2] fa 00 [2] e1 06 [2] fd 01 [2] e1 2e }

  condition:
    any of them
}