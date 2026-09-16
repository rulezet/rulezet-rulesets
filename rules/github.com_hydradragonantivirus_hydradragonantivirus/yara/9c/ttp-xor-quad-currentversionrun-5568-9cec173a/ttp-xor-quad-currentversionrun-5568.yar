rule TTP_XOR_QUAD_CurrentVersionRun_5568 {
  strings:
    $key_5568 = { 06 07 [2] 22 09 [2] 09 25 [2] 27 07 [2] 33 1c [2] 3c 06 [2] 22 1b [2] 20 1a [2] 3b 1c [2] 27 1b [2] 3b 34 }

  condition:
    any of them
}