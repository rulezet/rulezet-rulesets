rule TTP_XOR_QUAD_CurrentVersionRun_2815 {
  strings:
    $key_2815 = { 7b 7a [2] 5f 74 [2] 74 58 [2] 5a 7a [2] 4e 61 [2] 41 7b [2] 5f 66 [2] 5d 67 [2] 46 61 [2] 5a 66 [2] 46 49 }

  condition:
    any of them
}