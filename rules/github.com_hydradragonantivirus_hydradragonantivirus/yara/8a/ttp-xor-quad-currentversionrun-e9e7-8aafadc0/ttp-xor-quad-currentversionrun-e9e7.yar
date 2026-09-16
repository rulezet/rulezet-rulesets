rule TTP_XOR_QUAD_CurrentVersionRun_e9e7 {
  strings:
    $key_e9e7 = { ba 88 [2] 9e 86 [2] b5 aa [2] 9b 88 [2] 8f 93 [2] 80 89 [2] 9e 94 [2] 9c 95 [2] 87 93 [2] 9b 94 [2] 87 bb }

  condition:
    any of them
}