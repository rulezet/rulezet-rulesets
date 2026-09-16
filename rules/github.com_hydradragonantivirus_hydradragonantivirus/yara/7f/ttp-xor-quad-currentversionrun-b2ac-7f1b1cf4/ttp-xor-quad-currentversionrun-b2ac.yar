rule TTP_XOR_QUAD_CurrentVersionRun_b2ac {
  strings:
    $key_b2ac = { e1 c3 [2] c5 cd [2] ee e1 [2] c0 c3 [2] d4 d8 [2] db c2 [2] c5 df [2] c7 de [2] dc d8 [2] c0 df [2] dc f0 }

  condition:
    any of them
}