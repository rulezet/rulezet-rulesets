rule TTP_XOR_QUAD_CurrentVersionRun_ee92 {
  strings:
    $key_ee92 = { bd fd [2] 99 f3 [2] b2 df [2] 9c fd [2] 88 e6 [2] 87 fc [2] 99 e1 [2] 9b e0 [2] 80 e6 [2] 9c e1 [2] 80 ce }

  condition:
    any of them
}