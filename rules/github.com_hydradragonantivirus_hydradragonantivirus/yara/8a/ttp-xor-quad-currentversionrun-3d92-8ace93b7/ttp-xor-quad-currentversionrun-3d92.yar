rule TTP_XOR_QUAD_CurrentVersionRun_3d92 {
  strings:
    $key_3d92 = { 6e fd [2] 4a f3 [2] 61 df [2] 4f fd [2] 5b e6 [2] 54 fc [2] 4a e1 [2] 48 e0 [2] 53 e6 [2] 4f e1 [2] 53 ce }

  condition:
    any of them
}