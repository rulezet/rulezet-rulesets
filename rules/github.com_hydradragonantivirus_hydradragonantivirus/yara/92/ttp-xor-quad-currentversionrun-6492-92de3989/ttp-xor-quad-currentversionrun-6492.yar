rule TTP_XOR_QUAD_CurrentVersionRun_6492 {
  strings:
    $key_6492 = { 37 fd [2] 13 f3 [2] 38 df [2] 16 fd [2] 02 e6 [2] 0d fc [2] 13 e1 [2] 11 e0 [2] 0a e6 [2] 16 e1 [2] 0a ce }

  condition:
    any of them
}