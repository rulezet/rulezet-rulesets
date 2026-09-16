rule TTP_XOR_QUAD_CurrentVersionRun_63f8 {
  strings:
    $key_63f8 = { 30 97 [2] 14 99 [2] 3f b5 [2] 11 97 [2] 05 8c [2] 0a 96 [2] 14 8b [2] 16 8a [2] 0d 8c [2] 11 8b [2] 0d a4 }

  condition:
    any of them
}