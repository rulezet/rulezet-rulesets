rule TTP_XOR_QUAD_CurrentVersionRun_f627 {
  strings:
    $key_f627 = { a5 48 [2] 81 46 [2] aa 6a [2] 84 48 [2] 90 53 [2] 9f 49 [2] 81 54 [2] 83 55 [2] 98 53 [2] 84 54 [2] 98 7b }

  condition:
    any of them
}