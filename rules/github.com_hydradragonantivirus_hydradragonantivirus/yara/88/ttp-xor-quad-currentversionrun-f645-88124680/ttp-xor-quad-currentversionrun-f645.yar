rule TTP_XOR_QUAD_CurrentVersionRun_f645 {
  strings:
    $key_f645 = { a5 2a [2] 81 24 [2] aa 08 [2] 84 2a [2] 90 31 [2] 9f 2b [2] 81 36 [2] 83 37 [2] 98 31 [2] 84 36 [2] 98 19 }

  condition:
    any of them
}