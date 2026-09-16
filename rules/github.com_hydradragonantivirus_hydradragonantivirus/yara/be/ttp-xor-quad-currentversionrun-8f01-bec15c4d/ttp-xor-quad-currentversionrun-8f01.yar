rule TTP_XOR_QUAD_CurrentVersionRun_8f01 {
  strings:
    $key_8f01 = { dc 6e [2] f8 60 [2] d3 4c [2] fd 6e [2] e9 75 [2] e6 6f [2] f8 72 [2] fa 73 [2] e1 75 [2] fd 72 [2] e1 5d }

  condition:
    any of them
}