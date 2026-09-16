rule TTP_XOR_QUAD_CurrentVersionRun_2a48 {
  strings:
    $key_2a48 = { 79 27 [2] 5d 29 [2] 76 05 [2] 58 27 [2] 4c 3c [2] 43 26 [2] 5d 3b [2] 5f 3a [2] 44 3c [2] 58 3b [2] 44 14 }

  condition:
    any of them
}