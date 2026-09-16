rule TTP_XOR_QUAD_CurrentVersionRun_5235 {
  strings:
    $key_5235 = { 01 5a [2] 25 54 [2] 0e 78 [2] 20 5a [2] 34 41 [2] 3b 5b [2] 25 46 [2] 27 47 [2] 3c 41 [2] 20 46 [2] 3c 69 }

  condition:
    any of them
}