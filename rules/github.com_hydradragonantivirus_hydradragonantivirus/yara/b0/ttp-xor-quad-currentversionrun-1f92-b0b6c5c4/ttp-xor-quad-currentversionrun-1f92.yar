rule TTP_XOR_QUAD_CurrentVersionRun_1f92 {
  strings:
    $key_1f92 = { 4c fd [2] 68 f3 [2] 43 df [2] 6d fd [2] 79 e6 [2] 76 fc [2] 68 e1 [2] 6a e0 [2] 71 e6 [2] 6d e1 [2] 71 ce }

  condition:
    any of them
}