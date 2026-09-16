rule TTP_XOR_QUAD_CurrentVersionRun_2d79 {
  strings:
    $key_2d79 = { 7e 16 [2] 5a 18 [2] 71 34 [2] 5f 16 [2] 4b 0d [2] 44 17 [2] 5a 0a [2] 58 0b [2] 43 0d [2] 5f 0a [2] 43 25 }

  condition:
    any of them
}