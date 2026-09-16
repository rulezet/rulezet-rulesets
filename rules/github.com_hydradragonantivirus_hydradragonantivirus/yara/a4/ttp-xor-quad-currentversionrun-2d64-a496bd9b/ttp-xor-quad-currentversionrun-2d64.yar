rule TTP_XOR_QUAD_CurrentVersionRun_2d64 {
  strings:
    $key_2d64 = { 7e 0b [2] 5a 05 [2] 71 29 [2] 5f 0b [2] 4b 10 [2] 44 0a [2] 5a 17 [2] 58 16 [2] 43 10 [2] 5f 17 [2] 43 38 }

  condition:
    any of them
}