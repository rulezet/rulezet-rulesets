rule TTP_XOR_QUAD_CurrentVersionRun_33f8 {
  strings:
    $key_33f8 = { 60 97 [2] 44 99 [2] 6f b5 [2] 41 97 [2] 55 8c [2] 5a 96 [2] 44 8b [2] 46 8a [2] 5d 8c [2] 41 8b [2] 5d a4 }

  condition:
    any of them
}