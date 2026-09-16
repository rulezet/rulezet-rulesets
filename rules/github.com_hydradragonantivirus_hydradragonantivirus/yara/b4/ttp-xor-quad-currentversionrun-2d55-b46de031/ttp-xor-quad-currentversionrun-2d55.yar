rule TTP_XOR_QUAD_CurrentVersionRun_2d55 {
  strings:
    $key_2d55 = { 7e 3a [2] 5a 34 [2] 71 18 [2] 5f 3a [2] 4b 21 [2] 44 3b [2] 5a 26 [2] 58 27 [2] 43 21 [2] 5f 26 [2] 43 09 }

  condition:
    any of them
}