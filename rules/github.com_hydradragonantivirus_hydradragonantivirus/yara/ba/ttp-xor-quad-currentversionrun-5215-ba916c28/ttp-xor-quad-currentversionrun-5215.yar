rule TTP_XOR_QUAD_CurrentVersionRun_5215 {
  strings:
    $key_5215 = { 01 7a [2] 25 74 [2] 0e 58 [2] 20 7a [2] 34 61 [2] 3b 7b [2] 25 66 [2] 27 67 [2] 3c 61 [2] 20 66 [2] 3c 49 }

  condition:
    any of them
}