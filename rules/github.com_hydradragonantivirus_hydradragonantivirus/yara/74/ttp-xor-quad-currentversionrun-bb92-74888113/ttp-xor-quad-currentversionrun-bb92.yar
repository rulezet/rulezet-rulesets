rule TTP_XOR_QUAD_CurrentVersionRun_bb92 {
  strings:
    $key_bb92 = { e8 fd [2] cc f3 [2] e7 df [2] c9 fd [2] dd e6 [2] d2 fc [2] cc e1 [2] ce e0 [2] d5 e6 [2] c9 e1 [2] d5 ce }

  condition:
    any of them
}