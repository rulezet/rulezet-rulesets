rule TTP_XOR_QUAD_CurrentVersionRun_b792 {
  strings:
    $key_b792 = { e4 fd [2] c0 f3 [2] eb df [2] c5 fd [2] d1 e6 [2] de fc [2] c0 e1 [2] c2 e0 [2] d9 e6 [2] c5 e1 [2] d9 ce }

  condition:
    any of them
}