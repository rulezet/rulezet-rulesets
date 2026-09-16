rule TTP_XOR_QUAD_CurrentVersionRun_2a38 {
  strings:
    $key_2a38 = { 79 57 [2] 5d 59 [2] 76 75 [2] 58 57 [2] 4c 4c [2] 43 56 [2] 5d 4b [2] 5f 4a [2] 44 4c [2] 58 4b [2] 44 64 }

  condition:
    any of them
}