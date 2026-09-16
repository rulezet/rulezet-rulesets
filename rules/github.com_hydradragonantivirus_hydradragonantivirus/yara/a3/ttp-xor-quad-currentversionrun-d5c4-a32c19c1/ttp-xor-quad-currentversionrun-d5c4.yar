rule TTP_XOR_QUAD_CurrentVersionRun_d5c4 {
  strings:
    $key_d5c4 = { 86 ab [2] a2 a5 [2] 89 89 [2] a7 ab [2] b3 b0 [2] bc aa [2] a2 b7 [2] a0 b6 [2] bb b0 [2] a7 b7 [2] bb 98 }

  condition:
    any of them
}