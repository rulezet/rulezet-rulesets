rule TTP_XOR_QUAD_CurrentVersionRun_8ffd {
  strings:
    $key_8ffd = { dc 92 [2] f8 9c [2] d3 b0 [2] fd 92 [2] e9 89 [2] e6 93 [2] f8 8e [2] fa 8f [2] e1 89 [2] fd 8e [2] e1 a1 }

  condition:
    any of them
}