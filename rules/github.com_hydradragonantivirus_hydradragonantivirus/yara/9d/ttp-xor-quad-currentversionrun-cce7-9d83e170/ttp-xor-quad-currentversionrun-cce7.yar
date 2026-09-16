rule TTP_XOR_QUAD_CurrentVersionRun_cce7 {
  strings:
    $key_cce7 = { 9f 88 [2] bb 86 [2] 90 aa [2] be 88 [2] aa 93 [2] a5 89 [2] bb 94 [2] b9 95 [2] a2 93 [2] be 94 [2] a2 bb }

  condition:
    any of them
}