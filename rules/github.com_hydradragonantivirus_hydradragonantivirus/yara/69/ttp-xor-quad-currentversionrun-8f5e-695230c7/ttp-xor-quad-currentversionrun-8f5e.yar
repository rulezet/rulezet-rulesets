rule TTP_XOR_QUAD_CurrentVersionRun_8f5e {
  strings:
    $key_8f5e = { dc 31 [2] f8 3f [2] d3 13 [2] fd 31 [2] e9 2a [2] e6 30 [2] f8 2d [2] fa 2c [2] e1 2a [2] fd 2d [2] e1 02 }

  condition:
    any of them
}