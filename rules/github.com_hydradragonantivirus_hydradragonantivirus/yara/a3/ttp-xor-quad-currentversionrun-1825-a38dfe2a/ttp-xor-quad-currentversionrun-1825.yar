rule TTP_XOR_QUAD_CurrentVersionRun_1825 {
  strings:
    $key_1825 = { 4b 4a [2] 6f 44 [2] 44 68 [2] 6a 4a [2] 7e 51 [2] 71 4b [2] 6f 56 [2] 6d 57 [2] 76 51 [2] 6a 56 [2] 76 79 }

  condition:
    any of them
}