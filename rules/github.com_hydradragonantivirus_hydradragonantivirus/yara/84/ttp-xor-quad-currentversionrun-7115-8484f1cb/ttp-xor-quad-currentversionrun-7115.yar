rule TTP_XOR_QUAD_CurrentVersionRun_7115 {
  strings:
    $key_7115 = { 22 7a [2] 06 74 [2] 2d 58 [2] 03 7a [2] 17 61 [2] 18 7b [2] 06 66 [2] 04 67 [2] 1f 61 [2] 03 66 [2] 1f 49 }

  condition:
    any of them
}