rule TTP_XOR_QUAD_CurrentVersionRun_f635 {
  strings:
    $key_f635 = { a5 5a [2] 81 54 [2] aa 78 [2] 84 5a [2] 90 41 [2] 9f 5b [2] 81 46 [2] 83 47 [2] 98 41 [2] 84 46 [2] 98 69 }

  condition:
    any of them
}