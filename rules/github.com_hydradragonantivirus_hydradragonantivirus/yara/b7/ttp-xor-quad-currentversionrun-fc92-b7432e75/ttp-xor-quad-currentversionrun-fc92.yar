rule TTP_XOR_QUAD_CurrentVersionRun_fc92 {
  strings:
    $key_fc92 = { af fd [2] 8b f3 [2] a0 df [2] 8e fd [2] 9a e6 [2] 95 fc [2] 8b e1 [2] 89 e0 [2] 92 e6 [2] 8e e1 [2] 92 ce }

  condition:
    any of them
}