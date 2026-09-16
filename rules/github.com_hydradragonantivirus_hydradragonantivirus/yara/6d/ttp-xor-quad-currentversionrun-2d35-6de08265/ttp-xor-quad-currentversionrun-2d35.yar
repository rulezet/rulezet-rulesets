rule TTP_XOR_QUAD_CurrentVersionRun_2d35 {
  strings:
    $key_2d35 = { 7e 5a [2] 5a 54 [2] 71 78 [2] 5f 5a [2] 4b 41 [2] 44 5b [2] 5a 46 [2] 58 47 [2] 43 41 [2] 5f 46 [2] 43 69 }

  condition:
    any of them
}