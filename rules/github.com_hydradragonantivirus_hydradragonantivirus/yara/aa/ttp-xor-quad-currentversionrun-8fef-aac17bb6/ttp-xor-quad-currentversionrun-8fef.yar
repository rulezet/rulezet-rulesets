rule TTP_XOR_QUAD_CurrentVersionRun_8fef {
  strings:
    $key_8fef = { dc 80 [2] f8 8e [2] d3 a2 [2] fd 80 [2] e9 9b [2] e6 81 [2] f8 9c [2] fa 9d [2] e1 9b [2] fd 9c [2] e1 b3 }

  condition:
    any of them
}