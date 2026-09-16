rule TTP_XOR_QUAD_CurrentVersionRun_5492 {
  strings:
    $key_5492 = { 07 fd [2] 23 f3 [2] 08 df [2] 26 fd [2] 32 e6 [2] 3d fc [2] 23 e1 [2] 21 e0 [2] 3a e6 [2] 26 e1 [2] 3a ce }

  condition:
    any of them
}