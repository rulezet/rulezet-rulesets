rule TTP_XOR_QUAD_CurrentVersionRun_3f92 {
  strings:
    $key_3f92 = { 6c fd [2] 48 f3 [2] 63 df [2] 4d fd [2] 59 e6 [2] 56 fc [2] 48 e1 [2] 4a e0 [2] 51 e6 [2] 4d e1 [2] 51 ce }

  condition:
    any of them
}