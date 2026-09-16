rule TTP_XOR_QUAD_CurrentVersionRun_18f4 {
  strings:
    $key_18f4 = { 4b 9b [2] 6f 95 [2] 44 b9 [2] 6a 9b [2] 7e 80 [2] 71 9a [2] 6f 87 [2] 6d 86 [2] 76 80 [2] 6a 87 [2] 76 a8 }

  condition:
    any of them
}