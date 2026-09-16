rule TTP_XOR_QUAD_CurrentVersionRun_b892 {
  strings:
    $key_b892 = { eb fd [2] cf f3 [2] e4 df [2] ca fd [2] de e6 [2] d1 fc [2] cf e1 [2] cd e0 [2] d6 e6 [2] ca e1 [2] d6 ce }

  condition:
    any of them
}