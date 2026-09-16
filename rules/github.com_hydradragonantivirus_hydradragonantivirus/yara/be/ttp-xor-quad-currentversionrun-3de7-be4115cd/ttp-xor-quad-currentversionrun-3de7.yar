rule TTP_XOR_QUAD_CurrentVersionRun_3de7 {
  strings:
    $key_3de7 = { 6e 88 [2] 4a 86 [2] 61 aa [2] 4f 88 [2] 5b 93 [2] 54 89 [2] 4a 94 [2] 48 95 [2] 53 93 [2] 4f 94 [2] 53 bb }

  condition:
    any of them
}