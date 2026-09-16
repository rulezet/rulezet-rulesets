rule TTP_XOR_QUAD_CurrentVersionRun_1459 {
  strings:
    $key_1459 = { 47 36 [2] 63 38 [2] 48 14 [2] 66 36 [2] 72 2d [2] 7d 37 [2] 63 2a [2] 61 2b [2] 7a 2d [2] 66 2a [2] 7a 05 }

  condition:
    any of them
}