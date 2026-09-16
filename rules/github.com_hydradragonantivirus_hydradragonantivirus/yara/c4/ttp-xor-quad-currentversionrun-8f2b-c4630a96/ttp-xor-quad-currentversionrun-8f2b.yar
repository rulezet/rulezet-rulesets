rule TTP_XOR_QUAD_CurrentVersionRun_8f2b {
  strings:
    $key_8f2b = { dc 44 [2] f8 4a [2] d3 66 [2] fd 44 [2] e9 5f [2] e6 45 [2] f8 58 [2] fa 59 [2] e1 5f [2] fd 58 [2] e1 77 }

  condition:
    any of them
}