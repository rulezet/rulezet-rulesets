rule TTP_XOR_QUAD_CurrentVersionRun_5239 {
  strings:
    $key_5239 = { 01 56 [2] 25 58 [2] 0e 74 [2] 20 56 [2] 34 4d [2] 3b 57 [2] 25 4a [2] 27 4b [2] 3c 4d [2] 20 4a [2] 3c 65 }

  condition:
    any of them
}