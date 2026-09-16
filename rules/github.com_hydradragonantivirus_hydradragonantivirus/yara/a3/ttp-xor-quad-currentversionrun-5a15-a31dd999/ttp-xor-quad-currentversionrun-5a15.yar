rule TTP_XOR_QUAD_CurrentVersionRun_5a15 {
  strings:
    $key_5a15 = { 09 7a [2] 2d 74 [2] 06 58 [2] 28 7a [2] 3c 61 [2] 33 7b [2] 2d 66 [2] 2f 67 [2] 34 61 [2] 28 66 [2] 34 49 }

  condition:
    any of them
}