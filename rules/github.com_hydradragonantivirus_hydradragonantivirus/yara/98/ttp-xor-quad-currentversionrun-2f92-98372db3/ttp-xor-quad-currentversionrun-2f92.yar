rule TTP_XOR_QUAD_CurrentVersionRun_2f92 {
  strings:
    $key_2f92 = { 7c fd [2] 58 f3 [2] 73 df [2] 5d fd [2] 49 e6 [2] 46 fc [2] 58 e1 [2] 5a e0 [2] 41 e6 [2] 5d e1 [2] 41 ce }

  condition:
    any of them
}