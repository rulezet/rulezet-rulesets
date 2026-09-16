rule TTP_XOR_QUAD_CurrentVersionRun_5418 {
  strings:
    $key_5418 = { 07 77 [2] 23 79 [2] 08 55 [2] 26 77 [2] 32 6c [2] 3d 76 [2] 23 6b [2] 21 6a [2] 3a 6c [2] 26 6b [2] 3a 44 }

  condition:
    any of them
}