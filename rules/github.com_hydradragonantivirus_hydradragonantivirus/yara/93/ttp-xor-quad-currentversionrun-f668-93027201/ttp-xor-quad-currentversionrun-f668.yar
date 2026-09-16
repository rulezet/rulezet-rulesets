rule TTP_XOR_QUAD_CurrentVersionRun_f668 {
  strings:
    $key_f668 = { a5 07 [2] 81 09 [2] aa 25 [2] 84 07 [2] 90 1c [2] 9f 06 [2] 81 1b [2] 83 1a [2] 98 1c [2] 84 1b [2] 98 34 }

  condition:
    any of them
}