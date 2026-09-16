rule TTP_XOR_QUAD_CurrentVersionRun_8f79 {
  strings:
    $key_8f79 = { dc 16 [2] f8 18 [2] d3 34 [2] fd 16 [2] e9 0d [2] e6 17 [2] f8 0a [2] fa 0b [2] e1 0d [2] fd 0a [2] e1 25 }

  condition:
    any of them
}