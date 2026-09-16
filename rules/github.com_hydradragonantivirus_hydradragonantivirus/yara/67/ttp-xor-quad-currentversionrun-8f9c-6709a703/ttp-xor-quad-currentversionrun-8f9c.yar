rule TTP_XOR_QUAD_CurrentVersionRun_8f9c {
  strings:
    $key_8f9c = { dc f3 [2] f8 fd [2] d3 d1 [2] fd f3 [2] e9 e8 [2] e6 f2 [2] f8 ef [2] fa ee [2] e1 e8 [2] fd ef [2] e1 c0 }

  condition:
    any of them
}