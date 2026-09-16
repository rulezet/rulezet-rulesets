rule TTP_XOR_QUAD_CurrentVersionRun_8f69 {
  strings:
    $key_8f69 = { dc 06 [2] f8 08 [2] d3 24 [2] fd 06 [2] e9 1d [2] e6 07 [2] f8 1a [2] fa 1b [2] e1 1d [2] fd 1a [2] e1 35 }

  condition:
    any of them
}