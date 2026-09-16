rule TTP_XOR_QUAD_CurrentVersionRun_b592 {
  strings:
    $key_b592 = { e6 fd [2] c2 f3 [2] e9 df [2] c7 fd [2] d3 e6 [2] dc fc [2] c2 e1 [2] c0 e0 [2] db e6 [2] c7 e1 [2] db ce }

  condition:
    any of them
}