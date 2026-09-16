rule TTP_XOR_QUAD_CurrentVersionRun_1d92 {
  strings:
    $key_1d92 = { 4e fd [2] 6a f3 [2] 41 df [2] 6f fd [2] 7b e6 [2] 74 fc [2] 6a e1 [2] 68 e0 [2] 73 e6 [2] 6f e1 [2] 73 ce }

  condition:
    any of them
}