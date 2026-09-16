rule TTP_XOR_QUAD_CurrentVersionRun_f65b {
  strings:
    $key_f65b = { a5 34 [2] 81 3a [2] aa 16 [2] 84 34 [2] 90 2f [2] 9f 35 [2] 81 28 [2] 83 29 [2] 98 2f [2] 84 28 [2] 98 07 }

  condition:
    any of them
}