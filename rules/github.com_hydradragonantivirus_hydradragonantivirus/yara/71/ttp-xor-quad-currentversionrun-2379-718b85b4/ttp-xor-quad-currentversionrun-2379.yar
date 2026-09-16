rule TTP_XOR_QUAD_CurrentVersionRun_2379 {
  strings:
    $key_2379 = { 70 16 [2] 54 18 [2] 7f 34 [2] 51 16 [2] 45 0d [2] 4a 17 [2] 54 0a [2] 56 0b [2] 4d 0d [2] 51 0a [2] 4d 25 }

  condition:
    any of them
}