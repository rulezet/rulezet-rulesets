rule TTP_XOR_QUAD_CurrentVersionRun_8f5b {
  strings:
    $key_8f5b = { dc 34 [2] f8 3a [2] d3 16 [2] fd 34 [2] e9 2f [2] e6 35 [2] f8 28 [2] fa 29 [2] e1 2f [2] fd 28 [2] e1 07 }

  condition:
    any of them
}