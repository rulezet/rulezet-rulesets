rule TTP_XOR_QUAD_CurrentVersionRun_8f98 {
  strings:
    $key_8f98 = { dc f7 [2] f8 f9 [2] d3 d5 [2] fd f7 [2] e9 ec [2] e6 f6 [2] f8 eb [2] fa ea [2] e1 ec [2] fd eb [2] e1 c4 }

  condition:
    any of them
}