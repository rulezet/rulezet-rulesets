rule TTP_XOR_QUAD_CurrentVersionRun_2345 {
  strings:
    $key_2345 = { 70 2a [2] 54 24 [2] 7f 08 [2] 51 2a [2] 45 31 [2] 4a 2b [2] 54 36 [2] 56 37 [2] 4d 31 [2] 51 36 [2] 4d 19 }

  condition:
    any of them
}