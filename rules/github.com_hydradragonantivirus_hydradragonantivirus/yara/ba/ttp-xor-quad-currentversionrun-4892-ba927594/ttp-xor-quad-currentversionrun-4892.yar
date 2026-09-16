rule TTP_XOR_QUAD_CurrentVersionRun_4892 {
  strings:
    $key_4892 = { 1b fd [2] 3f f3 [2] 14 df [2] 3a fd [2] 2e e6 [2] 21 fc [2] 3f e1 [2] 3d e0 [2] 26 e6 [2] 3a e1 [2] 26 ce }

  condition:
    any of them
}