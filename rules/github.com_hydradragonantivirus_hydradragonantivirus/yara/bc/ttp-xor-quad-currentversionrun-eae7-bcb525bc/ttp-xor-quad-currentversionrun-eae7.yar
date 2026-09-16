rule TTP_XOR_QUAD_CurrentVersionRun_eae7 {
  strings:
    $key_eae7 = { b9 88 [2] 9d 86 [2] b6 aa [2] 98 88 [2] 8c 93 [2] 83 89 [2] 9d 94 [2] 9f 95 [2] 84 93 [2] 98 94 [2] 84 bb }

  condition:
    any of them
}