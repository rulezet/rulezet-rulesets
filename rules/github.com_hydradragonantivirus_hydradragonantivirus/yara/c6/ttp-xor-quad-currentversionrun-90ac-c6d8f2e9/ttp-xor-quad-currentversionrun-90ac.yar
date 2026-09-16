rule TTP_XOR_QUAD_CurrentVersionRun_90ac {
  strings:
    $key_90ac = { c3 c3 [2] e7 cd [2] cc e1 [2] e2 c3 [2] f6 d8 [2] f9 c2 [2] e7 df [2] e5 de [2] fe d8 [2] e2 df [2] fe f0 }

  condition:
    any of them
}