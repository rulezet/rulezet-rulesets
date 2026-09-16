rule TTP_XOR_QUAD_CurrentVersionRun_4678 {
  strings:
    $key_4678 = { 15 17 [2] 31 19 [2] 1a 35 [2] 34 17 [2] 20 0c [2] 2f 16 [2] 31 0b [2] 33 0a [2] 28 0c [2] 34 0b [2] 28 24 }

  condition:
    any of them
}