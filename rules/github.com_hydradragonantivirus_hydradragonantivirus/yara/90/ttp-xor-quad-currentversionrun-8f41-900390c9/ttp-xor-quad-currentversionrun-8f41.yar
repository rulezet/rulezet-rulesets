rule TTP_XOR_QUAD_CurrentVersionRun_8f41 {
  strings:
    $key_8f41 = { dc 2e [2] f8 20 [2] d3 0c [2] fd 2e [2] e9 35 [2] e6 2f [2] f8 32 [2] fa 33 [2] e1 35 [2] fd 32 [2] e1 1d }

  condition:
    any of them
}