rule TTP_XOR_QUAD_CurrentVersionRun_7318 {
  strings:
    $key_7318 = { 20 77 [2] 04 79 [2] 2f 55 [2] 01 77 [2] 15 6c [2] 1a 76 [2] 04 6b [2] 06 6a [2] 1d 6c [2] 01 6b [2] 1d 44 }

  condition:
    any of them
}