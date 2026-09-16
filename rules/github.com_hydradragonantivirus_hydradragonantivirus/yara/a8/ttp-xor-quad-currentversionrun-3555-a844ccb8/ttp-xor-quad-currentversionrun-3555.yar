rule TTP_XOR_QUAD_CurrentVersionRun_3555 {
  strings:
    $key_3555 = { 66 3a [2] 42 34 [2] 69 18 [2] 47 3a [2] 53 21 [2] 5c 3b [2] 42 26 [2] 40 27 [2] 5b 21 [2] 47 26 [2] 5b 09 }

  condition:
    any of them
}