rule TTP_XOR_QUAD_CurrentVersionRun_8fe1 {
  strings:
    $key_8fe1 = { dc 8e [2] f8 80 [2] d3 ac [2] fd 8e [2] e9 95 [2] e6 8f [2] f8 92 [2] fa 93 [2] e1 95 [2] fd 92 [2] e1 bd }

  condition:
    any of them
}