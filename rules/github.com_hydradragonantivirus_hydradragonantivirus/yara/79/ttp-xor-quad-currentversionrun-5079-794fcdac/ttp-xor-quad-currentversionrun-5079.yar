rule TTP_XOR_QUAD_CurrentVersionRun_5079 {
  strings:
    $key_5079 = { 03 16 [2] 27 18 [2] 0c 34 [2] 22 16 [2] 36 0d [2] 39 17 [2] 27 0a [2] 25 0b [2] 3e 0d [2] 22 0a [2] 3e 25 }

  condition:
    any of them
}