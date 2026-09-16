rule TTP_XOR_QUAD_CurrentVersionRun_5818 {
  strings:
    $key_5818 = { 0b 77 [2] 2f 79 [2] 04 55 [2] 2a 77 [2] 3e 6c [2] 31 76 [2] 2f 6b [2] 2d 6a [2] 36 6c [2] 2a 6b [2] 36 44 }

  condition:
    any of them
}