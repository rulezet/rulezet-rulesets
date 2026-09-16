rule TTP_XOR_QUAD_CurrentVersionRun_cec5 {
  strings:
    $key_cec5 = { 9d aa [2] b9 a4 [2] 92 88 [2] bc aa [2] a8 b1 [2] a7 ab [2] b9 b6 [2] bb b7 [2] a0 b1 [2] bc b6 [2] a0 99 }

  condition:
    any of them
}