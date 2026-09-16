rule TTP_XOR_QUAD_CurrentVersionRun_7108 {
  strings:
    $key_7108 = { 22 67 [2] 06 69 [2] 2d 45 [2] 03 67 [2] 17 7c [2] 18 66 [2] 06 7b [2] 04 7a [2] 1f 7c [2] 03 7b [2] 1f 54 }

  condition:
    any of them
}