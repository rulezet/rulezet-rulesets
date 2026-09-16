rule TTP_XOR_QUAD_CurrentVersionRun_4f64 {
  strings:
    $key_4f64 = { 1c 0b [2] 38 05 [2] 13 29 [2] 3d 0b [2] 29 10 [2] 26 0a [2] 38 17 [2] 3a 16 [2] 21 10 [2] 3d 17 [2] 21 38 }

  condition:
    any of them
}