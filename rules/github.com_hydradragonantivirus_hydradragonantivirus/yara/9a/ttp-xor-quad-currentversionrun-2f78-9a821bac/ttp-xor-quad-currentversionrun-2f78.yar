rule TTP_XOR_QUAD_CurrentVersionRun_2f78 {
  strings:
    $key_2f78 = { 7c 17 [2] 58 19 [2] 73 35 [2] 5d 17 [2] 49 0c [2] 46 16 [2] 58 0b [2] 5a 0a [2] 41 0c [2] 5d 0b [2] 41 24 }

  condition:
    any of them
}