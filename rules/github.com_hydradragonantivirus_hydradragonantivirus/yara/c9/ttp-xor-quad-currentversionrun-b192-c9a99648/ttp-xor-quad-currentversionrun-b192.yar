rule TTP_XOR_QUAD_CurrentVersionRun_b192 {
  strings:
    $key_b192 = { e2 fd [2] c6 f3 [2] ed df [2] c3 fd [2] d7 e6 [2] d8 fc [2] c6 e1 [2] c4 e0 [2] df e6 [2] c3 e1 [2] df ce }

  condition:
    any of them
}