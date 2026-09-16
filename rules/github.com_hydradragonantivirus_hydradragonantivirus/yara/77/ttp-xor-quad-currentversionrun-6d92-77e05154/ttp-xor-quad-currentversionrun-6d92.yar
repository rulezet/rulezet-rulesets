rule TTP_XOR_QUAD_CurrentVersionRun_6d92 {
  strings:
    $key_6d92 = { 3e fd [2] 1a f3 [2] 31 df [2] 1f fd [2] 0b e6 [2] 04 fc [2] 1a e1 [2] 18 e0 [2] 03 e6 [2] 1f e1 [2] 03 ce }

  condition:
    any of them
}