rule TTP_XOR_QUAD_CurrentVersionRun_5225 {
  strings:
    $key_5225 = { 01 4a [2] 25 44 [2] 0e 68 [2] 20 4a [2] 34 51 [2] 3b 4b [2] 25 56 [2] 27 57 [2] 3c 51 [2] 20 56 [2] 3c 79 }

  condition:
    any of them
}