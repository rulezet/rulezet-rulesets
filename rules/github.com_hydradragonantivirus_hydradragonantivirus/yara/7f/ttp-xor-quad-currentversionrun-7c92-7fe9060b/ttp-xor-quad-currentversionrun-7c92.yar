rule TTP_XOR_QUAD_CurrentVersionRun_7c92 {
  strings:
    $key_7c92 = { 2f fd [2] 0b f3 [2] 20 df [2] 0e fd [2] 1a e6 [2] 15 fc [2] 0b e1 [2] 09 e0 [2] 12 e6 [2] 0e e1 [2] 12 ce }

  condition:
    any of them
}