rule TTP_XOR_QUAD_CurrentVersionRun_7f18 {
  strings:
    $key_7f18 = { 2c 77 [2] 08 79 [2] 23 55 [2] 0d 77 [2] 19 6c [2] 16 76 [2] 08 6b [2] 0a 6a [2] 11 6c [2] 0d 6b [2] 11 44 }

  condition:
    any of them
}