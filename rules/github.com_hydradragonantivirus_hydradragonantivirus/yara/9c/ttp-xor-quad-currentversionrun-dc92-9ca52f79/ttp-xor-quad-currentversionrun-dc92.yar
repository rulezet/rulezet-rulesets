rule TTP_XOR_QUAD_CurrentVersionRun_dc92 {
  strings:
    $key_dc92 = { 8f fd [2] ab f3 [2] 80 df [2] ae fd [2] ba e6 [2] b5 fc [2] ab e1 [2] a9 e0 [2] b2 e6 [2] ae e1 [2] b2 ce }

  condition:
    any of them
}