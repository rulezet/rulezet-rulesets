rule TTP_XOR_QUAD_CurrentVersionRun_5a24 {
  strings:
    $key_5a24 = { 09 4b [2] 2d 45 [2] 06 69 [2] 28 4b [2] 3c 50 [2] 33 4a [2] 2d 57 [2] 2f 56 [2] 34 50 [2] 28 57 [2] 34 78 }

  condition:
    any of them
}