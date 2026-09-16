rule TTP_XOR_QUAD_CurrentVersionRun_0c92 {
  strings:
    $key_0c92 = { 5f fd [2] 7b f3 [2] 50 df [2] 7e fd [2] 6a e6 [2] 65 fc [2] 7b e1 [2] 79 e0 [2] 62 e6 [2] 7e e1 [2] 62 ce }

  condition:
    any of them
}