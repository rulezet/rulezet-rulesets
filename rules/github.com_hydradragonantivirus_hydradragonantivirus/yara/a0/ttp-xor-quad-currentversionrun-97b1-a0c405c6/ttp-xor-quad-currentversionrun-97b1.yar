rule TTP_XOR_QUAD_CurrentVersionRun_97b1 {
  strings:
    $key_97b1 = { c4 de [2] e0 d0 [2] cb fc [2] e5 de [2] f1 c5 [2] fe df [2] e0 c2 [2] e2 c3 [2] f9 c5 [2] e5 c2 [2] f9 ed }

  condition:
    any of them
}