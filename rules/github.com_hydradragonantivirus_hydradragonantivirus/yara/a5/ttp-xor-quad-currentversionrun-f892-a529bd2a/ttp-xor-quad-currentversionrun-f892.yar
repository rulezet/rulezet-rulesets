rule TTP_XOR_QUAD_CurrentVersionRun_f892 {
  strings:
    $key_f892 = { ab fd [2] 8f f3 [2] a4 df [2] 8a fd [2] 9e e6 [2] 91 fc [2] 8f e1 [2] 8d e0 [2] 96 e6 [2] 8a e1 [2] 96 ce }

  condition:
    any of them
}