rule TTP_XOR_QUAD_CurrentVersionRun_1844 {
  strings:
    $key_1844 = { 4b 2b [2] 6f 25 [2] 44 09 [2] 6a 2b [2] 7e 30 [2] 71 2a [2] 6f 37 [2] 6d 36 [2] 76 30 [2] 6a 37 [2] 76 18 }

  condition:
    any of them
}