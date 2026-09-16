rule TTP_XOR_QUAD_CurrentVersionRun_4f92 {
  strings:
    $key_4f92 = { 1c fd [2] 38 f3 [2] 13 df [2] 3d fd [2] 29 e6 [2] 26 fc [2] 38 e1 [2] 3a e0 [2] 21 e6 [2] 3d e1 [2] 21 ce }

  condition:
    any of them
}