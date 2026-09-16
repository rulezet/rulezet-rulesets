rule TTP_XOR_QUAD_CurrentVersionRun_fee7 {
  strings:
    $key_fee7 = { ad 88 [2] 89 86 [2] a2 aa [2] 8c 88 [2] 98 93 [2] 97 89 [2] 89 94 [2] 8b 95 [2] 90 93 [2] 8c 94 [2] 90 bb }

  condition:
    any of them
}