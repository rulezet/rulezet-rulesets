rule TTP_XOR_QUAD_CurrentVersionRun_ad92 {
  strings:
    $key_ad92 = { fe fd [2] da f3 [2] f1 df [2] df fd [2] cb e6 [2] c4 fc [2] da e1 [2] d8 e0 [2] c3 e6 [2] df e1 [2] c3 ce }

  condition:
    any of them
}