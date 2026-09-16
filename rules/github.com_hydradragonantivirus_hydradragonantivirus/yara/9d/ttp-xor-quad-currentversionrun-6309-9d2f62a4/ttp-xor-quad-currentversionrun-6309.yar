rule TTP_XOR_QUAD_CurrentVersionRun_6309 {
  strings:
    $key_6309 = { 30 66 [2] 14 68 [2] 3f 44 [2] 11 66 [2] 05 7d [2] 0a 67 [2] 14 7a [2] 16 7b [2] 0d 7d [2] 11 7a [2] 0d 55 }

  condition:
    any of them
}