rule TTP_XOR_QUAD_CurrentVersionRun_cc92 {
  strings:
    $key_cc92 = { 9f fd [2] bb f3 [2] 90 df [2] be fd [2] aa e6 [2] a5 fc [2] bb e1 [2] b9 e0 [2] a2 e6 [2] be e1 [2] a2 ce }

  condition:
    any of them
}