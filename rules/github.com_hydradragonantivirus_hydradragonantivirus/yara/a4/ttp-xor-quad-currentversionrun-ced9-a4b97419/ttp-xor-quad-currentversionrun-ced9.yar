rule TTP_XOR_QUAD_CurrentVersionRun_ced9 {
  strings:
    $key_ced9 = { 9d b6 [2] b9 b8 [2] 92 94 [2] bc b6 [2] a8 ad [2] a7 b7 [2] b9 aa [2] bb ab [2] a0 ad [2] bc aa [2] a0 85 }

  condition:
    any of them
}