rule TTP_XOR_QUAD_CurrentVersionRun_c892 {
  strings:
    $key_c892 = { 9b fd [2] bf f3 [2] 94 df [2] ba fd [2] ae e6 [2] a1 fc [2] bf e1 [2] bd e0 [2] a6 e6 [2] ba e1 [2] a6 ce }

  condition:
    any of them
}