rule TTP_XOR_QUAD_CurrentVersionRun_90b1 {
  strings:
    $key_90b1 = { c3 de [2] e7 d0 [2] cc fc [2] e2 de [2] f6 c5 [2] f9 df [2] e7 c2 [2] e5 c3 [2] fe c5 [2] e2 c2 [2] fe ed }

  condition:
    any of them
}