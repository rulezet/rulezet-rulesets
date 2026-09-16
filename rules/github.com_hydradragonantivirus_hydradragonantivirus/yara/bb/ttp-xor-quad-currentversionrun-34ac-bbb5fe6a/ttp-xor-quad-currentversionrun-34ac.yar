rule TTP_XOR_QUAD_CurrentVersionRun_34ac {
  strings:
    $key_34ac = { 67 c3 [2] 43 cd [2] 68 e1 [2] 46 c3 [2] 52 d8 [2] 5d c2 [2] 43 df [2] 41 de [2] 5a d8 [2] 46 df [2] 5a f0 }

  condition:
    any of them
}