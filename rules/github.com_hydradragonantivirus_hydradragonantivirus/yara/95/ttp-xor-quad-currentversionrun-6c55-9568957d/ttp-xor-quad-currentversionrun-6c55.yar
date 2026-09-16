rule TTP_XOR_QUAD_CurrentVersionRun_6c55 {
  strings:
    $key_6c55 = { 3f 3a [2] 1b 34 [2] 30 18 [2] 1e 3a [2] 0a 21 [2] 05 3b [2] 1b 26 [2] 19 27 [2] 02 21 [2] 1e 26 [2] 02 09 }

  condition:
    any of them
}