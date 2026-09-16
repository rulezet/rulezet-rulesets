rule TTP_XOR_QUAD_CurrentVersionRun_5068 {
  strings:
    $key_5068 = { 03 07 [2] 27 09 [2] 0c 25 [2] 22 07 [2] 36 1c [2] 39 06 [2] 27 1b [2] 25 1a [2] 3e 1c [2] 22 1b [2] 3e 34 }

  condition:
    any of them
}