rule TTP_XOR_QUAD_CurrentVersionRun_dde7 {
  strings:
    $key_dde7 = { 8e 88 [2] aa 86 [2] 81 aa [2] af 88 [2] bb 93 [2] b4 89 [2] aa 94 [2] a8 95 [2] b3 93 [2] af 94 [2] b3 bb }

  condition:
    any of them
}