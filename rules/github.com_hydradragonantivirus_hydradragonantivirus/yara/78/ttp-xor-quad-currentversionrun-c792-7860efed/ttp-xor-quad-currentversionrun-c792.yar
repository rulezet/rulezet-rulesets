rule TTP_XOR_QUAD_CurrentVersionRun_c792 {
  strings:
    $key_c792 = { 94 fd [2] b0 f3 [2] 9b df [2] b5 fd [2] a1 e6 [2] ae fc [2] b0 e1 [2] b2 e0 [2] a9 e6 [2] b5 e1 [2] a9 ce }

  condition:
    any of them
}