rule TTP_XOR_QUAD_CurrentVersionRun_1464 {
  strings:
    $key_1464 = { 47 0b [2] 63 05 [2] 48 29 [2] 66 0b [2] 72 10 [2] 7d 0a [2] 63 17 [2] 61 16 [2] 7a 10 [2] 66 17 [2] 7a 38 }

  condition:
    any of them
}