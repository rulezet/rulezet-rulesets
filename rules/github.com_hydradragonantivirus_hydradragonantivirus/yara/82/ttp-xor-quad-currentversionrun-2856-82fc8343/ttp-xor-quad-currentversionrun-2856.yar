rule TTP_XOR_QUAD_CurrentVersionRun_2856 {
  strings:
    $key_2856 = { 7b 39 [2] 5f 37 [2] 74 1b [2] 5a 39 [2] 4e 22 [2] 41 38 [2] 5f 25 [2] 5d 24 [2] 46 22 [2] 5a 25 [2] 46 0a }

  condition:
    any of them
}