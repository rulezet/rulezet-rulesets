rule TTP_XOR_QUAD_CurrentVersionRun_d092 {
  strings:
    $key_d092 = { 83 fd [2] a7 f3 [2] 8c df [2] a2 fd [2] b6 e6 [2] b9 fc [2] a7 e1 [2] a5 e0 [2] be e6 [2] a2 e1 [2] be ce }

  condition:
    any of them
}