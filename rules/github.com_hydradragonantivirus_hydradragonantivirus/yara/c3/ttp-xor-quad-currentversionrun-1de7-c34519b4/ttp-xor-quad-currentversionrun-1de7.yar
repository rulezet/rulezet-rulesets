rule TTP_XOR_QUAD_CurrentVersionRun_1de7 {
  strings:
    $key_1de7 = { 4e 88 [2] 6a 86 [2] 41 aa [2] 6f 88 [2] 7b 93 [2] 74 89 [2] 6a 94 [2] 68 95 [2] 73 93 [2] 6f 94 [2] 73 bb }

  condition:
    any of them
}