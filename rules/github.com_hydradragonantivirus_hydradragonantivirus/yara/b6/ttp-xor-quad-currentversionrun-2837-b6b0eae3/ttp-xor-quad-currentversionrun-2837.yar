rule TTP_XOR_QUAD_CurrentVersionRun_2837 {
  strings:
    $key_2837 = { 7b 58 [2] 5f 56 [2] 74 7a [2] 5a 58 [2] 4e 43 [2] 41 59 [2] 5f 44 [2] 5d 45 [2] 46 43 [2] 5a 44 [2] 46 6b }

  condition:
    any of them
}