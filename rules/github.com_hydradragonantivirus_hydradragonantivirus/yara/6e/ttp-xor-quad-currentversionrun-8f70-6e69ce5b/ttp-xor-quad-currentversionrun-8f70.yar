rule TTP_XOR_QUAD_CurrentVersionRun_8f70 {
  strings:
    $key_8f70 = { dc 1f [2] f8 11 [2] d3 3d [2] fd 1f [2] e9 04 [2] e6 1e [2] f8 03 [2] fa 02 [2] e1 04 [2] fd 03 [2] e1 2c }

  condition:
    any of them
}