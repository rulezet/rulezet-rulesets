rule TTP_XOR_QUAD_CurrentVersionRun_8ffc {
  strings:
    $key_8ffc = { dc 93 [2] f8 9d [2] d3 b1 [2] fd 93 [2] e9 88 [2] e6 92 [2] f8 8f [2] fa 8e [2] e1 88 [2] fd 8f [2] e1 a0 }

  condition:
    any of them
}