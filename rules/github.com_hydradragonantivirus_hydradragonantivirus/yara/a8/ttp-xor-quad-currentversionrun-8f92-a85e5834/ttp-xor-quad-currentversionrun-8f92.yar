rule TTP_XOR_QUAD_CurrentVersionRun_8f92 {
  strings:
    $key_8f92 = { dc fd [2] f8 f3 [2] d3 df [2] fd fd [2] e9 e6 [2] e6 fc [2] f8 e1 [2] fa e0 [2] e1 e6 [2] fd e1 [2] e1 ce }

  condition:
    any of them
}