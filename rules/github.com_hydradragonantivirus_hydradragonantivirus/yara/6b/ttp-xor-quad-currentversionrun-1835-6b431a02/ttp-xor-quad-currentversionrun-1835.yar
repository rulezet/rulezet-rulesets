rule TTP_XOR_QUAD_CurrentVersionRun_1835 {
  strings:
    $key_1835 = { 4b 5a [2] 6f 54 [2] 44 78 [2] 6a 5a [2] 7e 41 [2] 71 5b [2] 6f 46 [2] 6d 47 [2] 76 41 [2] 6a 46 [2] 76 69 }

  condition:
    any of them
}