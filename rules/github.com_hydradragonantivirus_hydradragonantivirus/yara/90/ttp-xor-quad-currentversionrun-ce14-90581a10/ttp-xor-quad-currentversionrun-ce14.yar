rule TTP_XOR_QUAD_CurrentVersionRun_ce14 {
  strings:
    $key_ce14 = { 9d 7b [2] b9 75 [2] 92 59 [2] bc 7b [2] a8 60 [2] a7 7a [2] b9 67 [2] bb 66 [2] a0 60 [2] bc 67 [2] a0 48 }

  condition:
    any of them
}