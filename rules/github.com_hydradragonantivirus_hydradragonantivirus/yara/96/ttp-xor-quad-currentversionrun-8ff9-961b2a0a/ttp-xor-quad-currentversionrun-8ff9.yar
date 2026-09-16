rule TTP_XOR_QUAD_CurrentVersionRun_8ff9 {
  strings:
    $key_8ff9 = { dc 96 [2] f8 98 [2] d3 b4 [2] fd 96 [2] e9 8d [2] e6 97 [2] f8 8a [2] fa 8b [2] e1 8d [2] fd 8a [2] e1 a5 }

  condition:
    any of them
}