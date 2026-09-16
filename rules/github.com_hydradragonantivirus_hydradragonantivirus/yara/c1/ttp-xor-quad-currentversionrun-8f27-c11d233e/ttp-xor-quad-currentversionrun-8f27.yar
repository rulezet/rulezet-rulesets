rule TTP_XOR_QUAD_CurrentVersionRun_8f27 {
  strings:
    $key_8f27 = { dc 48 [2] f8 46 [2] d3 6a [2] fd 48 [2] e9 53 [2] e6 49 [2] f8 54 [2] fa 55 [2] e1 53 [2] fd 54 [2] e1 7b }

  condition:
    any of them
}