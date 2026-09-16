rule TTP_XOR_QUAD_CurrentVersionRun_2835 {
  strings:
    $key_2835 = { 7b 5a [2] 5f 54 [2] 74 78 [2] 5a 5a [2] 4e 41 [2] 41 5b [2] 5f 46 [2] 5d 47 [2] 46 41 [2] 5a 46 [2] 46 69 }

  condition:
    any of them
}