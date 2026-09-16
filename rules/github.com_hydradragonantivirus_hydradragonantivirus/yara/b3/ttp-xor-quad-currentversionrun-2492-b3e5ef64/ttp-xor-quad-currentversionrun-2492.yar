rule TTP_XOR_QUAD_CurrentVersionRun_2492 {
  strings:
    $key_2492 = { 77 fd [2] 53 f3 [2] 78 df [2] 56 fd [2] 42 e6 [2] 4d fc [2] 53 e1 [2] 51 e0 [2] 4a e6 [2] 56 e1 [2] 4a ce }

  condition:
    any of them
}