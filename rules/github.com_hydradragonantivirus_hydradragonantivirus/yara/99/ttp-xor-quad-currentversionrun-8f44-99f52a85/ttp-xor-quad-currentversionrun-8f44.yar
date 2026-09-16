rule TTP_XOR_QUAD_CurrentVersionRun_8f44 {
  strings:
    $key_8f44 = { dc 2b [2] f8 25 [2] d3 09 [2] fd 2b [2] e9 30 [2] e6 2a [2] f8 37 [2] fa 36 [2] e1 30 [2] fd 37 [2] e1 18 }

  condition:
    any of them
}