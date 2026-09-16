rule TTP_XOR_QUAD_CurrentVersionRun_7518 {
  strings:
    $key_7518 = { 26 77 [2] 02 79 [2] 29 55 [2] 07 77 [2] 13 6c [2] 1c 76 [2] 02 6b [2] 00 6a [2] 1b 6c [2] 07 6b [2] 1b 44 }

  condition:
    any of them
}