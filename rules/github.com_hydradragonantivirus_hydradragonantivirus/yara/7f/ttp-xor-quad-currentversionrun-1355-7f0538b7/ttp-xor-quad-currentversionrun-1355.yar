rule TTP_XOR_QUAD_CurrentVersionRun_1355 {
  strings:
    $key_1355 = { 40 3a [2] 64 34 [2] 4f 18 [2] 61 3a [2] 75 21 [2] 7a 3b [2] 64 26 [2] 66 27 [2] 7d 21 [2] 61 26 [2] 7d 09 }

  condition:
    any of them
}