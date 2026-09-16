rule TTP_XOR_QUAD_CurrentVersionRun_8f36 {
  strings:
    $key_8f36 = { dc 59 [2] f8 57 [2] d3 7b [2] fd 59 [2] e9 42 [2] e6 58 [2] f8 45 [2] fa 44 [2] e1 42 [2] fd 45 [2] e1 6a }

  condition:
    any of them
}