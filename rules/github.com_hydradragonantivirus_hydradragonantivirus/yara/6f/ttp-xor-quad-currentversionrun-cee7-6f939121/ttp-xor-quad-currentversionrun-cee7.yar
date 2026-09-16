rule TTP_XOR_QUAD_CurrentVersionRun_cee7 {
  strings:
    $key_cee7 = { 9d 88 [2] b9 86 [2] 92 aa [2] bc 88 [2] a8 93 [2] a7 89 [2] b9 94 [2] bb 95 [2] a0 93 [2] bc 94 [2] a0 bb }

  condition:
    any of them
}