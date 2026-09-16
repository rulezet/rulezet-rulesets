rule TTP_XOR_QUAD_CurrentVersionRun_1856 {
  strings:
    $key_1856 = { 4b 39 [2] 6f 37 [2] 44 1b [2] 6a 39 [2] 7e 22 [2] 71 38 [2] 6f 25 [2] 6d 24 [2] 76 22 [2] 6a 25 [2] 76 0a }

  condition:
    any of them
}