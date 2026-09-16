rule TTP_XOR_QUAD_CurrentVersionRun_2858 {
  strings:
    $key_2858 = { 7b 37 [2] 5f 39 [2] 74 15 [2] 5a 37 [2] 4e 2c [2] 41 36 [2] 5f 2b [2] 5d 2a [2] 46 2c [2] 5a 2b [2] 46 04 }

  condition:
    any of them
}