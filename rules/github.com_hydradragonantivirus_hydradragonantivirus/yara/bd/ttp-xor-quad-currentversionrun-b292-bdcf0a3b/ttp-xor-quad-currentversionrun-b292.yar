rule TTP_XOR_QUAD_CurrentVersionRun_b292 {
  strings:
    $key_b292 = { e1 fd [2] c5 f3 [2] ee df [2] c0 fd [2] d4 e6 [2] db fc [2] c5 e1 [2] c7 e0 [2] dc e6 [2] c0 e1 [2] dc ce }

  condition:
    any of them
}