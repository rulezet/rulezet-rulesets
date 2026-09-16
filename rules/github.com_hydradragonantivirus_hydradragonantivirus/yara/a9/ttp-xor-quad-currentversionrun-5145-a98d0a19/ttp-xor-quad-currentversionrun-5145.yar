rule TTP_XOR_QUAD_CurrentVersionRun_5145 {
  strings:
    $key_5145 = { 02 2a [2] 26 24 [2] 0d 08 [2] 23 2a [2] 37 31 [2] 38 2b [2] 26 36 [2] 24 37 [2] 3f 31 [2] 23 36 [2] 3f 19 }

  condition:
    any of them
}