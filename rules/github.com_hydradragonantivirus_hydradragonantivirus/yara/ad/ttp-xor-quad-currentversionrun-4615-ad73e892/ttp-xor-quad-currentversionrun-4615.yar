rule TTP_XOR_QUAD_CurrentVersionRun_4615 {
  strings:
    $key_4615 = { 15 7a [2] 31 74 [2] 1a 58 [2] 34 7a [2] 20 61 [2] 2f 7b [2] 31 66 [2] 33 67 [2] 28 61 [2] 34 66 [2] 28 49 }

  condition:
    any of them
}