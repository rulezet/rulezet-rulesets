rule TTP_XOR_QUAD_CurrentVersionRun_3492 {
  strings:
    $key_3492 = { 67 fd [2] 43 f3 [2] 68 df [2] 46 fd [2] 52 e6 [2] 5d fc [2] 43 e1 [2] 41 e0 [2] 5a e6 [2] 46 e1 [2] 5a ce }

  condition:
    any of them
}