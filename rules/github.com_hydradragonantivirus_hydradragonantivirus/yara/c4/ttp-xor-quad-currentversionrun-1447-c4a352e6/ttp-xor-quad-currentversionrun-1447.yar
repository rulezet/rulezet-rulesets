rule TTP_XOR_QUAD_CurrentVersionRun_1447 {
  strings:
    $key_1447 = { 47 28 [2] 63 26 [2] 48 0a [2] 66 28 [2] 72 33 [2] 7d 29 [2] 63 34 [2] 61 35 [2] 7a 33 [2] 66 34 [2] 7a 1b }

  condition:
    any of them
}