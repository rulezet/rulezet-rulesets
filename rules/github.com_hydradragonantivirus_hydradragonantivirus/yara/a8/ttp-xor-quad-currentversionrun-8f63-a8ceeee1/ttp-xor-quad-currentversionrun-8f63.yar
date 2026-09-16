rule TTP_XOR_QUAD_CurrentVersionRun_8f63 {
  strings:
    $key_8f63 = { dc 0c [2] f8 02 [2] d3 2e [2] fd 0c [2] e9 17 [2] e6 0d [2] f8 10 [2] fa 11 [2] e1 17 [2] fd 10 [2] e1 3f }

  condition:
    any of them
}