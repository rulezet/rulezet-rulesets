rule TTP_XOR_QUAD_CurrentVersionRun_6408 {
  strings:
    $key_6408 = { 37 67 [2] 13 69 [2] 38 45 [2] 16 67 [2] 02 7c [2] 0d 66 [2] 13 7b [2] 11 7a [2] 0a 7c [2] 16 7b [2] 0a 54 }

  condition:
    any of them
}