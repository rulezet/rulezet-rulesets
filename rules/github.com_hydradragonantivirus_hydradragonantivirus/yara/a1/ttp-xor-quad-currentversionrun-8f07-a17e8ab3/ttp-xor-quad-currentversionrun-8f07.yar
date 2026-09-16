rule TTP_XOR_QUAD_CurrentVersionRun_8f07 {
  strings:
    $key_8f07 = { dc 68 [2] f8 66 [2] d3 4a [2] fd 68 [2] e9 73 [2] e6 69 [2] f8 74 [2] fa 75 [2] e1 73 [2] fd 74 [2] e1 5b }

  condition:
    any of them
}