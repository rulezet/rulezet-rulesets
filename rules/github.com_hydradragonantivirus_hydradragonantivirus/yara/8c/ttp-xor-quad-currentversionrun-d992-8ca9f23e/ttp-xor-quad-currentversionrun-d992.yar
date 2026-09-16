rule TTP_XOR_QUAD_CurrentVersionRun_d992 {
  strings:
    $key_d992 = { 8a fd [2] ae f3 [2] 85 df [2] ab fd [2] bf e6 [2] b0 fc [2] ae e1 [2] ac e0 [2] b7 e6 [2] ab e1 [2] b7 ce }

  condition:
    any of them
}