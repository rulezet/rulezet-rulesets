rule TTP_XOR_QUAD_CurrentVersionRun_6992 {
  strings:
    $key_6992 = { 3a fd [2] 1e f3 [2] 35 df [2] 1b fd [2] 0f e6 [2] 00 fc [2] 1e e1 [2] 1c e0 [2] 07 e6 [2] 1b e1 [2] 07 ce }

  condition:
    any of them
}