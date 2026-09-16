rule TTP_XOR_QUAD_CurrentVersionRun_3ae7 {
  strings:
    $key_3ae7 = { 69 88 [2] 4d 86 [2] 66 aa [2] 48 88 [2] 5c 93 [2] 53 89 [2] 4d 94 [2] 4f 95 [2] 54 93 [2] 48 94 [2] 54 bb }

  condition:
    any of them
}