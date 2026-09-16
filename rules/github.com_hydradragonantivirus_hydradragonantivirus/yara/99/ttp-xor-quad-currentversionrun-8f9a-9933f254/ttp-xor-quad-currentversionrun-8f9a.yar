rule TTP_XOR_QUAD_CurrentVersionRun_8f9a {
  strings:
    $key_8f9a = { dc f5 [2] f8 fb [2] d3 d7 [2] fd f5 [2] e9 ee [2] e6 f4 [2] f8 e9 [2] fa e8 [2] e1 ee [2] fd e9 [2] e1 c6 }

  condition:
    any of them
}