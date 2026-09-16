rule TTP_XOR_QUAD_CurrentVersionRun_6a92 {
  strings:
    $key_6a92 = { 39 fd [2] 1d f3 [2] 36 df [2] 18 fd [2] 0c e6 [2] 03 fc [2] 1d e1 [2] 1f e0 [2] 04 e6 [2] 18 e1 [2] 04 ce }

  condition:
    any of them
}