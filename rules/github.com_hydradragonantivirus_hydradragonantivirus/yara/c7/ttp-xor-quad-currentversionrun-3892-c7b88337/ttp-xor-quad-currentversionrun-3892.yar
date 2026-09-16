rule TTP_XOR_QUAD_CurrentVersionRun_3892 {
  strings:
    $key_3892 = { 6b fd [2] 4f f3 [2] 64 df [2] 4a fd [2] 5e e6 [2] 51 fc [2] 4f e1 [2] 4d e0 [2] 56 e6 [2] 4a e1 [2] 56 ce }

  condition:
    any of them
}