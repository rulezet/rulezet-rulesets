rule TTP_XOR_QUAD_CurrentVersionRun_30ac {
  strings:
    $key_30ac = { 63 c3 [2] 47 cd [2] 6c e1 [2] 42 c3 [2] 56 d8 [2] 59 c2 [2] 47 df [2] 45 de [2] 5e d8 [2] 42 df [2] 5e f0 }

  condition:
    any of them
}