rule TTP_XOR_QUAD_CurrentVersionRun_4e92 {
  strings:
    $key_4e92 = { 1d fd [2] 39 f3 [2] 12 df [2] 3c fd [2] 28 e6 [2] 27 fc [2] 39 e1 [2] 3b e0 [2] 20 e6 [2] 3c e1 [2] 20 ce }

  condition:
    any of them
}