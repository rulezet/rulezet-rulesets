rule TTP_XOR_QUAD_CurrentVersionRun_ed92 {
  strings:
    $key_ed92 = { be fd [2] 9a f3 [2] b1 df [2] 9f fd [2] 8b e6 [2] 84 fc [2] 9a e1 [2] 98 e0 [2] 83 e6 [2] 9f e1 [2] 83 ce }

  condition:
    any of them
}