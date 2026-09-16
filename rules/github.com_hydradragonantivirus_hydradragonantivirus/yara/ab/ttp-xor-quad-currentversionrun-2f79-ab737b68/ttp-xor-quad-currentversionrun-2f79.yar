rule TTP_XOR_QUAD_CurrentVersionRun_2f79 {
  strings:
    $key_2f79 = { 7c 16 [2] 58 18 [2] 73 34 [2] 5d 16 [2] 49 0d [2] 46 17 [2] 58 0a [2] 5a 0b [2] 41 0d [2] 5d 0a [2] 41 25 }

  condition:
    any of them
}