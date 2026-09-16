rule TTP_XOR_QUAD_CurrentVersionRun_8f7c {
  strings:
    $key_8f7c = { dc 13 [2] f8 1d [2] d3 31 [2] fd 13 [2] e9 08 [2] e6 12 [2] f8 0f [2] fa 0e [2] e1 08 [2] fd 0f [2] e1 20 }

  condition:
    any of them
}