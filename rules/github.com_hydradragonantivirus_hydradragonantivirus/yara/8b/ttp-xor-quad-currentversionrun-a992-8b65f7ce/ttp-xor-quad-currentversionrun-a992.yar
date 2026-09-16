rule TTP_XOR_QUAD_CurrentVersionRun_a992 {
  strings:
    $key_a992 = { fa fd [2] de f3 [2] f5 df [2] db fd [2] cf e6 [2] c0 fc [2] de e1 [2] dc e0 [2] c7 e6 [2] db e1 [2] c7 ce }

  condition:
    any of them
}