rule TTP_XOR_QUAD_CurrentVersionRun_ff92 {
  strings:
    $key_ff92 = { ac fd [2] 88 f3 [2] a3 df [2] 8d fd [2] 99 e6 [2] 96 fc [2] 88 e1 [2] 8a e0 [2] 91 e6 [2] 8d e1 [2] 91 ce }

  condition:
    any of them
}