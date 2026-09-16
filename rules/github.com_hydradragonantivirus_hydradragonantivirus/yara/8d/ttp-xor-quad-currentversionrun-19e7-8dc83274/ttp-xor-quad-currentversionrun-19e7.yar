rule TTP_XOR_QUAD_CurrentVersionRun_19e7 {
  strings:
    $key_19e7 = { 4a 88 [2] 6e 86 [2] 45 aa [2] 6b 88 [2] 7f 93 [2] 70 89 [2] 6e 94 [2] 6c 95 [2] 77 93 [2] 6b 94 [2] 77 bb }

  condition:
    any of them
}