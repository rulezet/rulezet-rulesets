rule TTP_XOR_QUAD_CurrentVersionRun_d5d9 {
  strings:
    $key_d5d9 = { 86 b6 [2] a2 b8 [2] 89 94 [2] a7 b6 [2] b3 ad [2] bc b7 [2] a2 aa [2] a0 ab [2] bb ad [2] a7 aa [2] bb 85 }

  condition:
    any of them
}