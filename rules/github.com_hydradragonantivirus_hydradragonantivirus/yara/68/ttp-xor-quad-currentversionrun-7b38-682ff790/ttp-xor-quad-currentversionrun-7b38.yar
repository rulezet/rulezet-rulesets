rule TTP_XOR_QUAD_CurrentVersionRun_7b38 {
  strings:
    $key_7b38 = { 28 57 [2] 0c 59 [2] 27 75 [2] 09 57 [2] 1d 4c [2] 12 56 [2] 0c 4b [2] 0e 4a [2] 15 4c [2] 09 4b [2] 15 64 }

  condition:
    any of them
}