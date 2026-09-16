rule TTP_XOR_QUAD_CurrentVersionRun_d7e7 {
  strings:
    $key_d7e7 = { 84 88 [2] a0 86 [2] 8b aa [2] a5 88 [2] b1 93 [2] be 89 [2] a0 94 [2] a2 95 [2] b9 93 [2] a5 94 [2] b9 bb }

  condition:
    any of them
}