rule TTP_XOR_QUAD_CurrentVersionRun_f628 {
  strings:
    $key_f628 = { a5 47 [2] 81 49 [2] aa 65 [2] 84 47 [2] 90 5c [2] 9f 46 [2] 81 5b [2] 83 5a [2] 98 5c [2] 84 5b [2] 98 74 }

  condition:
    any of them
}