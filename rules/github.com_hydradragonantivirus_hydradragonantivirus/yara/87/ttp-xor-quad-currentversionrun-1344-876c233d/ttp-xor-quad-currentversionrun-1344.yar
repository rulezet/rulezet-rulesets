rule TTP_XOR_QUAD_CurrentVersionRun_1344 {
  strings:
    $key_1344 = { 40 2b [2] 64 25 [2] 4f 09 [2] 61 2b [2] 75 30 [2] 7a 2a [2] 64 37 [2] 66 36 [2] 7d 30 [2] 61 37 [2] 7d 18 }

  condition:
    any of them
}