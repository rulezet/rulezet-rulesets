rule TTP_XOR_QUAD_CurrentVersionRun_21ac {
  strings:
    $key_21ac = { 72 c3 [2] 56 cd [2] 7d e1 [2] 53 c3 [2] 47 d8 [2] 48 c2 [2] 56 df [2] 54 de [2] 4f d8 [2] 53 df [2] 4f f0 }

  condition:
    any of them
}