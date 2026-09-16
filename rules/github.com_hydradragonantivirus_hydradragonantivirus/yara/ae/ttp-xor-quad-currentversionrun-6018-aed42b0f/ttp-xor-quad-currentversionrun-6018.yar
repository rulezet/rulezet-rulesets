rule TTP_XOR_QUAD_CurrentVersionRun_6018 {
  strings:
    $key_6018 = { 33 77 [2] 17 79 [2] 3c 55 [2] 12 77 [2] 06 6c [2] 09 76 [2] 17 6b [2] 15 6a [2] 0e 6c [2] 12 6b [2] 0e 44 }

  condition:
    any of them
}