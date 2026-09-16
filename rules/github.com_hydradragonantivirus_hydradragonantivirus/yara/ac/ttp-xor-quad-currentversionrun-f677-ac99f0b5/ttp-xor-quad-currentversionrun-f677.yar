rule TTP_XOR_QUAD_CurrentVersionRun_f677 {
  strings:
    $key_f677 = { a5 18 [2] 81 16 [2] aa 3a [2] 84 18 [2] 90 03 [2] 9f 19 [2] 81 04 [2] 83 05 [2] 98 03 [2] 84 04 [2] 98 2b }

  condition:
    any of them
}