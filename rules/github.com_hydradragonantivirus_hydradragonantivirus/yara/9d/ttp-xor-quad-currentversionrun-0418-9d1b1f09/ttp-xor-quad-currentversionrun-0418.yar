rule TTP_XOR_QUAD_CurrentVersionRun_0418 {
  strings:
    $key_0418 = { 57 77 [2] 73 79 [2] 58 55 [2] 76 77 [2] 62 6c [2] 6d 76 [2] 73 6b [2] 71 6a [2] 6a 6c [2] 76 6b [2] 6a 44 }

  condition:
    any of them
}