rule TTP_XOR_QUAD_CurrentVersionRun_f8e7 {
  strings:
    $key_f8e7 = { ab 88 [2] 8f 86 [2] a4 aa [2] 8a 88 [2] 9e 93 [2] 91 89 [2] 8f 94 [2] 8d 95 [2] 96 93 [2] 8a 94 [2] 96 bb }

  condition:
    any of them
}