rule TTP_XOR_QUAD_CurrentVersionRun_5992 {
  strings:
    $key_5992 = { 0a fd [2] 2e f3 [2] 05 df [2] 2b fd [2] 3f e6 [2] 30 fc [2] 2e e1 [2] 2c e0 [2] 37 e6 [2] 2b e1 [2] 37 ce }

  condition:
    any of them
}