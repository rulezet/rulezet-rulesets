rule TTP_XOR_QUAD_CurrentVersionRun_cd92 {
  strings:
    $key_cd92 = { 9e fd [2] ba f3 [2] 91 df [2] bf fd [2] ab e6 [2] a4 fc [2] ba e1 [2] b8 e0 [2] a3 e6 [2] bf e1 [2] a3 ce }

  condition:
    any of them
}