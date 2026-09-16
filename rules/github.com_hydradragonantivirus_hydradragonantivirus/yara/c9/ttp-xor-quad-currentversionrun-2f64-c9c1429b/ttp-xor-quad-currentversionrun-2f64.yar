rule TTP_XOR_QUAD_CurrentVersionRun_2f64 {
  strings:
    $key_2f64 = { 7c 0b [2] 58 05 [2] 73 29 [2] 5d 0b [2] 49 10 [2] 46 0a [2] 58 17 [2] 5a 16 [2] 41 10 [2] 5d 17 [2] 41 38 }

  condition:
    any of them
}