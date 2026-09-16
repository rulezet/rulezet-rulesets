rule TTP_XOR_QUAD_CurrentVersionRun_2f45 {
  strings:
    $key_2f45 = { 7c 2a [2] 58 24 [2] 73 08 [2] 5d 2a [2] 49 31 [2] 46 2b [2] 58 36 [2] 5a 37 [2] 41 31 [2] 5d 36 [2] 41 19 }

  condition:
    any of them
}