rule TTP_XOR_QUAD_CurrentVersionRun_14ac {
  strings:
    $key_14ac = { 47 c3 [2] 63 cd [2] 48 e1 [2] 66 c3 [2] 72 d8 [2] 7d c2 [2] 63 df [2] 61 de [2] 7a d8 [2] 66 df [2] 7a f0 }

  condition:
    any of them
}