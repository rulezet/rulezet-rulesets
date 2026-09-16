rule TTP_XOR_QUAD_CurrentVersionRun_f607 {
  strings:
    $key_f607 = { a5 68 [2] 81 66 [2] aa 4a [2] 84 68 [2] 90 73 [2] 9f 69 [2] 81 74 [2] 83 75 [2] 98 73 [2] 84 74 [2] 98 5b }

  condition:
    any of them
}