rule TTP_XOR_QUAD_CurrentVersionRun_8f5c {
  strings:
    $key_8f5c = { dc 33 [2] f8 3d [2] d3 11 [2] fd 33 [2] e9 28 [2] e6 32 [2] f8 2f [2] fa 2e [2] e1 28 [2] fd 2f [2] e1 00 }

  condition:
    any of them
}