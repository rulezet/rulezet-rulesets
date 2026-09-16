rule TTP_XOR_QUAD_CurrentVersionRun_1834 {
  strings:
    $key_1834 = { 4b 5b [2] 6f 55 [2] 44 79 [2] 6a 5b [2] 7e 40 [2] 71 5a [2] 6f 47 [2] 6d 46 [2] 76 40 [2] 6a 47 [2] 76 68 }

  condition:
    any of them
}