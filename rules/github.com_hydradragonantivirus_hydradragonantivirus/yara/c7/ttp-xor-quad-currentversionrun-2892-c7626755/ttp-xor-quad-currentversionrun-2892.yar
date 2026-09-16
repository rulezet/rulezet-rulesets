rule TTP_XOR_QUAD_CurrentVersionRun_2892 {
  strings:
    $key_2892 = { 7b fd [2] 5f f3 [2] 74 df [2] 5a fd [2] 4e e6 [2] 41 fc [2] 5f e1 [2] 5d e0 [2] 46 e6 [2] 5a e1 [2] 46 ce }

  condition:
    any of them
}