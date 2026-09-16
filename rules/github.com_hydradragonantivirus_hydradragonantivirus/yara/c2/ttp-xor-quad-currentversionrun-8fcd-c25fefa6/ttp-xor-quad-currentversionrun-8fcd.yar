rule TTP_XOR_QUAD_CurrentVersionRun_8fcd {
  strings:
    $key_8fcd = { dc a2 [2] f8 ac [2] d3 80 [2] fd a2 [2] e9 b9 [2] e6 a3 [2] f8 be [2] fa bf [2] e1 b9 [2] fd be [2] e1 91 }

  condition:
    any of them
}