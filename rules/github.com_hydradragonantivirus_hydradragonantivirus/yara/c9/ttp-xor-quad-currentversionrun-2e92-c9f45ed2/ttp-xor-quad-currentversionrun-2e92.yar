rule TTP_XOR_QUAD_CurrentVersionRun_2e92 {
  strings:
    $key_2e92 = { 7d fd [2] 59 f3 [2] 72 df [2] 5c fd [2] 48 e6 [2] 47 fc [2] 59 e1 [2] 5b e0 [2] 40 e6 [2] 5c e1 [2] 40 ce }

  condition:
    any of them
}