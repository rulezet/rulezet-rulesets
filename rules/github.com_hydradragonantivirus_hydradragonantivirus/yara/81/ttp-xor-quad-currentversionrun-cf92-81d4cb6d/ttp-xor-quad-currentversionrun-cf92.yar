rule TTP_XOR_QUAD_CurrentVersionRun_cf92 {
  strings:
    $key_cf92 = { 9c fd [2] b8 f3 [2] 93 df [2] bd fd [2] a9 e6 [2] a6 fc [2] b8 e1 [2] ba e0 [2] a1 e6 [2] bd e1 [2] a1 ce }

  condition:
    any of them
}