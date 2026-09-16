rule TTP_XOR_QUAD_CurrentVersionRun_90ad {
  strings:
    $key_90ad = { c3 c2 [2] e7 cc [2] cc e0 [2] e2 c2 [2] f6 d9 [2] f9 c3 [2] e7 de [2] e5 df [2] fe d9 [2] e2 de [2] fe f1 }

  condition:
    any of them
}