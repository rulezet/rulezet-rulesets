rule TTP_XOR_QUAD_CurrentVersionRun_3be7 {
  strings:
    $key_3be7 = { 68 88 [2] 4c 86 [2] 67 aa [2] 49 88 [2] 5d 93 [2] 52 89 [2] 4c 94 [2] 4e 95 [2] 55 93 [2] 49 94 [2] 55 bb }

  condition:
    any of them
}