rule TTP_XOR_QUAD_CurrentVersionRun_5d92 {
  strings:
    $key_5d92 = { 0e fd [2] 2a f3 [2] 01 df [2] 2f fd [2] 3b e6 [2] 34 fc [2] 2a e1 [2] 28 e0 [2] 33 e6 [2] 2f e1 [2] 33 ce }

  condition:
    any of them
}