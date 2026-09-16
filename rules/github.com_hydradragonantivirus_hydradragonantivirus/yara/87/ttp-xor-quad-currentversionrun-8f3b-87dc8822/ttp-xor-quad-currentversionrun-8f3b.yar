rule TTP_XOR_QUAD_CurrentVersionRun_8f3b {
  strings:
    $key_8f3b = { dc 54 [2] f8 5a [2] d3 76 [2] fd 54 [2] e9 4f [2] e6 55 [2] f8 48 [2] fa 49 [2] e1 4f [2] fd 48 [2] e1 67 }

  condition:
    any of them
}