rule TTP_XOR_QUAD_CurrentVersionRun_5a08 {
  strings:
    $key_5a08 = { 09 67 [2] 2d 69 [2] 06 45 [2] 28 67 [2] 3c 7c [2] 33 66 [2] 2d 7b [2] 2f 7a [2] 34 7c [2] 28 7b [2] 34 54 }

  condition:
    any of them
}