rule TTP_XOR_QUAD_CurrentVersionRun_2825 {
  strings:
    $key_2825 = { 7b 4a [2] 5f 44 [2] 74 68 [2] 5a 4a [2] 4e 51 [2] 41 4b [2] 5f 56 [2] 5d 57 [2] 46 51 [2] 5a 56 [2] 46 79 }

  condition:
    any of them
}