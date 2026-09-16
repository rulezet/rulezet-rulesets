rule TTP_XOR_QUAD_CurrentVersionRun_1454 {
  strings:
    $key_1454 = { 47 3b [2] 63 35 [2] 48 19 [2] 66 3b [2] 72 20 [2] 7d 3a [2] 63 27 [2] 61 26 [2] 7a 20 [2] 66 27 [2] 7a 08 }

  condition:
    any of them
}