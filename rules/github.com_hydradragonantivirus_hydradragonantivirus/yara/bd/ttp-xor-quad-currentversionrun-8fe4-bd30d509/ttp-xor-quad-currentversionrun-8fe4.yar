rule TTP_XOR_QUAD_CurrentVersionRun_8fe4 {
  strings:
    $key_8fe4 = { dc 8b [2] f8 85 [2] d3 a9 [2] fd 8b [2] e9 90 [2] e6 8a [2] f8 97 [2] fa 96 [2] e1 90 [2] fd 97 [2] e1 b8 }

  condition:
    any of them
}