rule TTP_XOR_QUAD_CurrentVersionRun_4e55 {
  strings:
    $key_4e55 = { 1d 3a [2] 39 34 [2] 12 18 [2] 3c 3a [2] 28 21 [2] 27 3b [2] 39 26 [2] 3b 27 [2] 20 21 [2] 3c 26 [2] 20 09 }

  condition:
    any of them
}