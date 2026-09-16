rule TTP_XOR_QUAD_CurrentVersionRun_6418 {
  strings:
    $key_6418 = { 37 77 [2] 13 79 [2] 38 55 [2] 16 77 [2] 02 6c [2] 0d 76 [2] 13 6b [2] 11 6a [2] 0a 6c [2] 16 6b [2] 0a 44 }

  condition:
    any of them
}