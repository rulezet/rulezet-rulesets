rule TTP_XOR_QUAD_CurrentVersionRun_dfe7 {
  strings:
    $key_dfe7 = { 8c 88 [2] a8 86 [2] 83 aa [2] ad 88 [2] b9 93 [2] b6 89 [2] a8 94 [2] aa 95 [2] b1 93 [2] ad 94 [2] b1 bb }

  condition:
    any of them
}