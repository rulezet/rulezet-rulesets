rule TTP_XOR_QUAD_CurrentVersionRun_0e48 {
  strings:
    $key_0e48 = { 5d 27 [2] 79 29 [2] 52 05 [2] 7c 27 [2] 68 3c [2] 67 26 [2] 79 3b [2] 7b 3a [2] 60 3c [2] 7c 3b [2] 60 14 }

  condition:
    any of them
}