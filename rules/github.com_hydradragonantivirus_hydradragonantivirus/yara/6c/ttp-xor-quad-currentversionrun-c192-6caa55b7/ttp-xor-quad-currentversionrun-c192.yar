rule TTP_XOR_QUAD_CurrentVersionRun_c192 {
  strings:
    $key_c192 = { 92 fd [2] b6 f3 [2] 9d df [2] b3 fd [2] a7 e6 [2] a8 fc [2] b6 e1 [2] b4 e0 [2] af e6 [2] b3 e1 [2] af ce }

  condition:
    any of them
}