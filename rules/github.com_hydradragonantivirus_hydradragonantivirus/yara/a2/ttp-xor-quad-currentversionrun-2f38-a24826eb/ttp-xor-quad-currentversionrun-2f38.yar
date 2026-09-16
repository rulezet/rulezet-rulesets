rule TTP_XOR_QUAD_CurrentVersionRun_2f38 {
  strings:
    $key_2f38 = { 7c 57 [2] 58 59 [2] 73 75 [2] 5d 57 [2] 49 4c [2] 46 56 [2] 58 4b [2] 5a 4a [2] 41 4c [2] 5d 4b [2] 41 64 }

  condition:
    any of them
}