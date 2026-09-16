rule TTP_XOR_QUAD_CurrentVersionRun_2be7 {
  strings:
    $key_2be7 = { 78 88 [2] 5c 86 [2] 77 aa [2] 59 88 [2] 4d 93 [2] 42 89 [2] 5c 94 [2] 5e 95 [2] 45 93 [2] 59 94 [2] 45 bb }

  condition:
    any of them
}