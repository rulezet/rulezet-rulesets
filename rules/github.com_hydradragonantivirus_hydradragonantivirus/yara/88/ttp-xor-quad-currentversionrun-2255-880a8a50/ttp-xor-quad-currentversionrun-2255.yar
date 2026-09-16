rule TTP_XOR_QUAD_CurrentVersionRun_2255 {
  strings:
    $key_2255 = { 71 3a [2] 55 34 [2] 7e 18 [2] 50 3a [2] 44 21 [2] 4b 3b [2] 55 26 [2] 57 27 [2] 4c 21 [2] 50 26 [2] 4c 09 }

  condition:
    any of them
}