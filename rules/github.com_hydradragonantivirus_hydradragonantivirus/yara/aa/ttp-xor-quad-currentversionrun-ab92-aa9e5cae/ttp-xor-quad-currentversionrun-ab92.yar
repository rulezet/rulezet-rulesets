rule TTP_XOR_QUAD_CurrentVersionRun_ab92 {
  strings:
    $key_ab92 = { f8 fd [2] dc f3 [2] f7 df [2] d9 fd [2] cd e6 [2] c2 fc [2] dc e1 [2] de e0 [2] c5 e6 [2] d9 e1 [2] c5 ce }

  condition:
    any of them
}