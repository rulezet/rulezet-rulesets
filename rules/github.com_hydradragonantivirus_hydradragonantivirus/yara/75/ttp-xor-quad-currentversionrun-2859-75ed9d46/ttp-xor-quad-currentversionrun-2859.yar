rule TTP_XOR_QUAD_CurrentVersionRun_2859 {
  strings:
    $key_2859 = { 7b 36 [2] 5f 38 [2] 74 14 [2] 5a 36 [2] 4e 2d [2] 41 37 [2] 5f 2a [2] 5d 2b [2] 46 2d [2] 5a 2a [2] 46 05 }

  condition:
    any of them
}