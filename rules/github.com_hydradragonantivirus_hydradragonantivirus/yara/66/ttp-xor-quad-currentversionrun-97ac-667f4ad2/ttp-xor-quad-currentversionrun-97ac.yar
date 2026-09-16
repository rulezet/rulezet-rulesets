rule TTP_XOR_QUAD_CurrentVersionRun_97ac {
  strings:
    $key_97ac = { c4 c3 [2] e0 cd [2] cb e1 [2] e5 c3 [2] f1 d8 [2] fe c2 [2] e0 df [2] e2 de [2] f9 d8 [2] e5 df [2] f9 f0 }

  condition:
    any of them
}