rule TTP_XOR_QUAD_CurrentVersionRun_5179 {
  strings:
    $key_5179 = { 02 16 [2] 26 18 [2] 0d 34 [2] 23 16 [2] 37 0d [2] 38 17 [2] 26 0a [2] 24 0b [2] 3f 0d [2] 23 0a [2] 3f 25 }

  condition:
    any of them
}