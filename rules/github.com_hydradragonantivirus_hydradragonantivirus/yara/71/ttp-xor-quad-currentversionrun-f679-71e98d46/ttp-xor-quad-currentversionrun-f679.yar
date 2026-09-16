rule TTP_XOR_QUAD_CurrentVersionRun_f679 {
  strings:
    $key_f679 = { a5 16 [2] 81 18 [2] aa 34 [2] 84 16 [2] 90 0d [2] 9f 17 [2] 81 0a [2] 83 0b [2] 98 0d [2] 84 0a [2] 98 25 }

  condition:
    any of them
}