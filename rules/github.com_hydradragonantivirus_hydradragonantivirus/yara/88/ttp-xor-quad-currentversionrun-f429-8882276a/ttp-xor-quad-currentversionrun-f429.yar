rule TTP_XOR_QUAD_CurrentVersionRun_f429 {
  strings:
    $key_f429 = { a7 46 [2] 83 48 [2] a8 64 [2] 86 46 [2] 92 5d [2] 9d 47 [2] 83 5a [2] 81 5b [2] 9a 5d [2] 86 5a [2] 9a 75 }

  condition:
    any of them
}