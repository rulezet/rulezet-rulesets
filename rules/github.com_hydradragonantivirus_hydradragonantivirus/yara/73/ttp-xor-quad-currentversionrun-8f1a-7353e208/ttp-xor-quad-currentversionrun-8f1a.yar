rule TTP_XOR_QUAD_CurrentVersionRun_8f1a {
  strings:
    $key_8f1a = { dc 75 [2] f8 7b [2] d3 57 [2] fd 75 [2] e9 6e [2] e6 74 [2] f8 69 [2] fa 68 [2] e1 6e [2] fd 69 [2] e1 46 }

  condition:
    any of them
}