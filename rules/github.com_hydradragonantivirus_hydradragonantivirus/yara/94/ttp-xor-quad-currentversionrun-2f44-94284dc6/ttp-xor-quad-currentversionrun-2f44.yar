rule TTP_XOR_QUAD_CurrentVersionRun_2f44 {
  strings:
    $key_2f44 = { 7c 2b [2] 58 25 [2] 73 09 [2] 5d 2b [2] 49 30 [2] 46 2a [2] 58 37 [2] 5a 36 [2] 41 30 [2] 5d 37 [2] 41 18 }

  condition:
    any of them
}