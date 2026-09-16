rule TTP_XOR_QUAD_CurrentVersionRun_8f2c {
  strings:
    $key_8f2c = { dc 43 [2] f8 4d [2] d3 61 [2] fd 43 [2] e9 58 [2] e6 42 [2] f8 5f [2] fa 5e [2] e1 58 [2] fd 5f [2] e1 70 }

  condition:
    any of them
}