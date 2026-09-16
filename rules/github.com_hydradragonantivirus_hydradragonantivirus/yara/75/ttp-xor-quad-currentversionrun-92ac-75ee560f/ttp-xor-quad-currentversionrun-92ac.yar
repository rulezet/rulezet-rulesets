rule TTP_XOR_QUAD_CurrentVersionRun_92ac {
  strings:
    $key_92ac = { c1 c3 [2] e5 cd [2] ce e1 [2] e0 c3 [2] f4 d8 [2] fb c2 [2] e5 df [2] e7 de [2] fc d8 [2] e0 df [2] fc f0 }

  condition:
    any of them
}