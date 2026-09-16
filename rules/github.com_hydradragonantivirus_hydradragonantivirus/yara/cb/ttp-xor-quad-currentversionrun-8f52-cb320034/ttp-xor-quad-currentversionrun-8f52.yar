rule TTP_XOR_QUAD_CurrentVersionRun_8f52 {
  strings:
    $key_8f52 = { dc 3d [2] f8 33 [2] d3 1f [2] fd 3d [2] e9 26 [2] e6 3c [2] f8 21 [2] fa 20 [2] e1 26 [2] fd 21 [2] e1 0e }

  condition:
    any of them
}