rule TTP_XOR_QUAD_CurrentVersionRun_5d15 {
  strings:
    $key_5d15 = { 0e 7a [2] 2a 74 [2] 01 58 [2] 2f 7a [2] 3b 61 [2] 34 7b [2] 2a 66 [2] 28 67 [2] 33 61 [2] 2f 66 [2] 33 49 }

  condition:
    any of them
}