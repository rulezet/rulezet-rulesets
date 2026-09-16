rule TTP_XOR_QUAD_CurrentVersionRun_3979 {
  strings:
    $key_3979 = { 6a 16 [2] 4e 18 [2] 65 34 [2] 4b 16 [2] 5f 0d [2] 50 17 [2] 4e 0a [2] 4c 0b [2] 57 0d [2] 4b 0a [2] 57 25 }

  condition:
    any of them
}