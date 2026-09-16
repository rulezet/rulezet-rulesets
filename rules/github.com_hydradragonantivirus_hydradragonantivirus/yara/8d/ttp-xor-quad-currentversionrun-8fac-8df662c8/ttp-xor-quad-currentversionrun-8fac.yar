rule TTP_XOR_QUAD_CurrentVersionRun_8fac {
  strings:
    $key_8fac = { dc c3 [2] f8 cd [2] d3 e1 [2] fd c3 [2] e9 d8 [2] e6 c2 [2] f8 df [2] fa de [2] e1 d8 [2] fd df [2] e1 f0 }

  condition:
    any of them
}