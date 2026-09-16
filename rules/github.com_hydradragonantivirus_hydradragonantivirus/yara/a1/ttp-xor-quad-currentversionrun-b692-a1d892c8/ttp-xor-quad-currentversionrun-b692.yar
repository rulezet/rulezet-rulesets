rule TTP_XOR_QUAD_CurrentVersionRun_b692 {
  strings:
    $key_b692 = { e5 fd [2] c1 f3 [2] ea df [2] c4 fd [2] d0 e6 [2] df fc [2] c1 e1 [2] c3 e0 [2] d8 e6 [2] c4 e1 [2] d8 ce }

  condition:
    any of them
}