rule TTP_XOR_QUAD_CurrentVersionRun_f647 {
  strings:
    $key_f647 = { a5 28 [2] 81 26 [2] aa 0a [2] 84 28 [2] 90 33 [2] 9f 29 [2] 81 34 [2] 83 35 [2] 98 33 [2] 84 34 [2] 98 1b }

  condition:
    any of them
}