rule TTP_XOR_QUAD_CurrentVersionRun_4635 {
  strings:
    $key_4635 = { 15 5a [2] 31 54 [2] 1a 78 [2] 34 5a [2] 20 41 [2] 2f 5b [2] 31 46 [2] 33 47 [2] 28 41 [2] 34 46 [2] 28 69 }

  condition:
    any of them
}