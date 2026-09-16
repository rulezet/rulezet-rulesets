rule TTP_XOR_QUAD_CurrentVersionRun_5a2b {
  strings:
    $key_5a2b = { 09 44 [2] 2d 4a [2] 06 66 [2] 28 44 [2] 3c 5f [2] 33 45 [2] 2d 58 [2] 2f 59 [2] 34 5f [2] 28 58 [2] 34 77 }

  condition:
    any of them
}