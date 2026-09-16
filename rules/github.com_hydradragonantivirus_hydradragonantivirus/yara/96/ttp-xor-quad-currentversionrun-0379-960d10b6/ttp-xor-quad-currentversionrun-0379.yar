rule TTP_XOR_QUAD_CurrentVersionRun_0379 {
  strings:
    $key_0379 = { 50 16 [2] 74 18 [2] 5f 34 [2] 71 16 [2] 65 0d [2] 6a 17 [2] 74 0a [2] 76 0b [2] 6d 0d [2] 71 0a [2] 6d 25 }

  condition:
    any of them
}