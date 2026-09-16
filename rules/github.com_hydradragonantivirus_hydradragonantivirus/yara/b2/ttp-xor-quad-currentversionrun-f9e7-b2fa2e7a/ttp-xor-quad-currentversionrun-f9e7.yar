rule TTP_XOR_QUAD_CurrentVersionRun_f9e7 {
  strings:
    $key_f9e7 = { aa 88 [2] 8e 86 [2] a5 aa [2] 8b 88 [2] 9f 93 [2] 90 89 [2] 8e 94 [2] 8c 95 [2] 97 93 [2] 8b 94 [2] 97 bb }

  condition:
    any of them
}