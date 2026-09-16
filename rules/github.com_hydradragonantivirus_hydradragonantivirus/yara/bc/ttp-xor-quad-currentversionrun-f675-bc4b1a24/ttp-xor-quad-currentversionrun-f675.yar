rule TTP_XOR_QUAD_CurrentVersionRun_f675 {
  strings:
    $key_f675 = { a5 1a [2] 81 14 [2] aa 38 [2] 84 1a [2] 90 01 [2] 9f 1b [2] 81 06 [2] 83 07 [2] 98 01 [2] 84 06 [2] 98 29 }

  condition:
    any of them
}