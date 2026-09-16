rule TTP_XOR_QUAD_CurrentVersionRun_fd92 {
  strings:
    $key_fd92 = { ae fd [2] 8a f3 [2] a1 df [2] 8f fd [2] 9b e6 [2] 94 fc [2] 8a e1 [2] 88 e0 [2] 93 e6 [2] 8f e1 [2] 93 ce }

  condition:
    any of them
}