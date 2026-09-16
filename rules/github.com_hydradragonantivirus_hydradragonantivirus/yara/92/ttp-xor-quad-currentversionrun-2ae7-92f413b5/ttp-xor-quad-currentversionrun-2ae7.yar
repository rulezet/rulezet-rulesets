rule TTP_XOR_QUAD_CurrentVersionRun_2ae7 {
  strings:
    $key_2ae7 = { 79 88 [2] 5d 86 [2] 76 aa [2] 58 88 [2] 4c 93 [2] 43 89 [2] 5d 94 [2] 5f 95 [2] 44 93 [2] 58 94 [2] 44 bb }

  condition:
    any of them
}