rule TTP_XOR_QUAD_CurrentVersionRun_1879 {
  strings:
    $key_1879 = { 4b 16 [2] 6f 18 [2] 44 34 [2] 6a 16 [2] 7e 0d [2] 71 17 [2] 6f 0a [2] 6d 0b [2] 76 0d [2] 6a 0a [2] 76 25 }

  condition:
    any of them
}