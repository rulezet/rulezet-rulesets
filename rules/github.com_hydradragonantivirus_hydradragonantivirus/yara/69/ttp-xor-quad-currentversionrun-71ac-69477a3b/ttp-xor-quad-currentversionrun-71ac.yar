rule TTP_XOR_QUAD_CurrentVersionRun_71ac {
  strings:
    $key_71ac = { 22 c3 [2] 06 cd [2] 2d e1 [2] 03 c3 [2] 17 d8 [2] 18 c2 [2] 06 df [2] 04 de [2] 1f d8 [2] 03 df [2] 1f f0 }

  condition:
    any of them
}