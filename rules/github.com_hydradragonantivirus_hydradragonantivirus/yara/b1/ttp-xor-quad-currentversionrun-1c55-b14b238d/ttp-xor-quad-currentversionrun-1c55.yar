rule TTP_XOR_QUAD_CurrentVersionRun_1c55 {
  strings:
    $key_1c55 = { 4f 3a [2] 6b 34 [2] 40 18 [2] 6e 3a [2] 7a 21 [2] 75 3b [2] 6b 26 [2] 69 27 [2] 72 21 [2] 6e 26 [2] 72 09 }

  condition:
    any of them
}