rule TTP_XOR_QUAD_CurrentVersionRun_2992 {
  strings:
    $key_2992 = { 7a fd [2] 5e f3 [2] 75 df [2] 5b fd [2] 4f e6 [2] 40 fc [2] 5e e1 [2] 5c e0 [2] 47 e6 [2] 5b e1 [2] 47 ce }

  condition:
    any of them
}