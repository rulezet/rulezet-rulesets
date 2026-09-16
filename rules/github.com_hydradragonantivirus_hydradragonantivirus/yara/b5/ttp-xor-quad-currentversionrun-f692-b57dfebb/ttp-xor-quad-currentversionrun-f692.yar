rule TTP_XOR_QUAD_CurrentVersionRun_f692 {
  strings:
    $key_f692 = { a5 fd [2] 81 f3 [2] aa df [2] 84 fd [2] 90 e6 [2] 9f fc [2] 81 e1 [2] 83 e0 [2] 98 e6 [2] 84 e1 [2] 98 ce }

  condition:
    any of them
}