rule TTP_XOR_QUAD_CurrentVersionRun_7408 {
  strings:
    $key_7408 = { 27 67 [2] 03 69 [2] 28 45 [2] 06 67 [2] 12 7c [2] 1d 66 [2] 03 7b [2] 01 7a [2] 1a 7c [2] 06 7b [2] 1a 54 }

  condition:
    any of them
}