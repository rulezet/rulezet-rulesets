rule TTP_XOR_QUAD_CurrentVersionRun_2354 {
  strings:
    $key_2354 = { 70 3b [2] 54 35 [2] 7f 19 [2] 51 3b [2] 45 20 [2] 4a 3a [2] 54 27 [2] 56 26 [2] 4d 20 [2] 51 27 [2] 4d 08 }

  condition:
    any of them
}