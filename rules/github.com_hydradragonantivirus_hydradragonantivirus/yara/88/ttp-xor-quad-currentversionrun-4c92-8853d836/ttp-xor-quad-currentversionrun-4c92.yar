rule TTP_XOR_QUAD_CurrentVersionRun_4c92 {
  strings:
    $key_4c92 = { 1f fd [2] 3b f3 [2] 10 df [2] 3e fd [2] 2a e6 [2] 25 fc [2] 3b e1 [2] 39 e0 [2] 22 e6 [2] 3e e1 [2] 22 ce }

  condition:
    any of them
}