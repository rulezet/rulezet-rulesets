rule TTP_XOR_QUAD_CurrentVersionRun_d2d8 {
  strings:
    $key_d2d8 = { 81 b7 [2] a5 b9 [2] 8e 95 [2] a0 b7 [2] b4 ac [2] bb b6 [2] a5 ab [2] a7 aa [2] bc ac [2] a0 ab [2] bc 84 }

  condition:
    any of them
}