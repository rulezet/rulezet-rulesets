rule TTP_XOR_QUAD_CurrentVersionRun_53ac {
  strings:
    $key_53ac = { 00 c3 [2] 24 cd [2] 0f e1 [2] 21 c3 [2] 35 d8 [2] 3a c2 [2] 24 df [2] 26 de [2] 3d d8 [2] 21 df [2] 3d f0 }

  condition:
    any of them
}