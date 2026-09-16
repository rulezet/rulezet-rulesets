rule TTP_XOR_QUAD_CurrentVersionRun_5245 {
  strings:
    $key_5245 = { 01 2a [2] 25 24 [2] 0e 08 [2] 20 2a [2] 34 31 [2] 3b 2b [2] 25 36 [2] 27 37 [2] 3c 31 [2] 20 36 [2] 3c 19 }

  condition:
    any of them
}