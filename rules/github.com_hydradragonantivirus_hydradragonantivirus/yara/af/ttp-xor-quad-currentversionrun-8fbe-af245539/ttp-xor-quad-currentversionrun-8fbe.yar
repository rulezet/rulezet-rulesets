rule TTP_XOR_QUAD_CurrentVersionRun_8fbe {
  strings:
    $key_8fbe = { dc d1 [2] f8 df [2] d3 f3 [2] fd d1 [2] e9 ca [2] e6 d0 [2] f8 cd [2] fa cc [2] e1 ca [2] fd cd [2] e1 e2 }

  condition:
    any of them
}