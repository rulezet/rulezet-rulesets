rule TTP_XOR_QUAD_CurrentVersionRun_ce99 {
  strings:
    $key_ce99 = { 9d f6 [2] b9 f8 [2] 92 d4 [2] bc f6 [2] a8 ed [2] a7 f7 [2] b9 ea [2] bb eb [2] a0 ed [2] bc ea [2] a0 c5 }

  condition:
    any of them
}