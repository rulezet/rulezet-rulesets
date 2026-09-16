rule TTP_XOR_QUAD_CurrentVersionRun_6838 {
  strings:
    $key_6838 = { 3b 57 [2] 1f 59 [2] 34 75 [2] 1a 57 [2] 0e 4c [2] 01 56 [2] 1f 4b [2] 1d 4a [2] 06 4c [2] 1a 4b [2] 06 64 }

  condition:
    any of them
}