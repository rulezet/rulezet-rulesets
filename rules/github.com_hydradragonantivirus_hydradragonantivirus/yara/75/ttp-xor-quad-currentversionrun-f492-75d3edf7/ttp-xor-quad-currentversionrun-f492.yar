rule TTP_XOR_QUAD_CurrentVersionRun_f492 {
  strings:
    $key_f492 = { a7 fd [2] 83 f3 [2] a8 df [2] 86 fd [2] 92 e6 [2] 9d fc [2] 83 e1 [2] 81 e0 [2] 9a e6 [2] 86 e1 [2] 9a ce }

  condition:
    any of them
}