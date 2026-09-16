rule TTP_XOR_QUAD_CurrentVersionRun_7f64 {
  strings:
    $key_7f64 = { 2c 0b [2] 08 05 [2] 23 29 [2] 0d 0b [2] 19 10 [2] 16 0a [2] 08 17 [2] 0a 16 [2] 11 10 [2] 0d 17 [2] 11 38 }

  condition:
    any of them
}