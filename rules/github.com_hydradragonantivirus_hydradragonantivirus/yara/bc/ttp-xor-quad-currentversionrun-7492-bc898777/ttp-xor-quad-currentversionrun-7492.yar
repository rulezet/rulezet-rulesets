rule TTP_XOR_QUAD_CurrentVersionRun_7492 {
  strings:
    $key_7492 = { 27 fd [2] 03 f3 [2] 28 df [2] 06 fd [2] 12 e6 [2] 1d fc [2] 03 e1 [2] 01 e0 [2] 1a e6 [2] 06 e1 [2] 1a ce }

  condition:
    any of them
}