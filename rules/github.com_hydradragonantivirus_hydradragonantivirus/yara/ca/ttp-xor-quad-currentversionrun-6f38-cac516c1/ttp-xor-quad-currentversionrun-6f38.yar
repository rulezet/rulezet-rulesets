rule TTP_XOR_QUAD_CurrentVersionRun_6f38 {
  strings:
    $key_6f38 = { 3c 57 [2] 18 59 [2] 33 75 [2] 1d 57 [2] 09 4c [2] 06 56 [2] 18 4b [2] 1a 4a [2] 01 4c [2] 1d 4b [2] 01 64 }

  condition:
    any of them
}