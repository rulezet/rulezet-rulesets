rule TTP_XOR_QUAD_CurrentVersionRun_2555 {
  strings:
    $key_2555 = { 76 3a [2] 52 34 [2] 79 18 [2] 57 3a [2] 43 21 [2] 4c 3b [2] 52 26 [2] 50 27 [2] 4b 21 [2] 57 26 [2] 4b 09 }

  condition:
    any of them
}