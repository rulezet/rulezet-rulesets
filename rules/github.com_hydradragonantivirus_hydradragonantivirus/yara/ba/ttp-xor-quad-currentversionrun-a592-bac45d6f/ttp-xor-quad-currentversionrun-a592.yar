rule TTP_XOR_QUAD_CurrentVersionRun_a592 {
  strings:
    $key_a592 = { f6 fd [2] d2 f3 [2] f9 df [2] d7 fd [2] c3 e6 [2] cc fc [2] d2 e1 [2] d0 e0 [2] cb e6 [2] d7 e1 [2] cb ce }

  condition:
    any of them
}