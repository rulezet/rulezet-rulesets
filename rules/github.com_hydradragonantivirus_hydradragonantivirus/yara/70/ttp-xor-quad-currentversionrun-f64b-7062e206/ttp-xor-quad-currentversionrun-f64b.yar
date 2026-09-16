rule TTP_XOR_QUAD_CurrentVersionRun_f64b {
  strings:
    $key_f64b = { a5 24 [2] 81 2a [2] aa 06 [2] 84 24 [2] 90 3f [2] 9f 25 [2] 81 38 [2] 83 39 [2] 98 3f [2] 84 38 [2] 98 17 }

  condition:
    any of them
}