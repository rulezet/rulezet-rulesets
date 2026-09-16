rule TTP_XOR_QUAD_CurrentVersionRun_0e55 {
  strings:
    $key_0e55 = { 5d 3a [2] 79 34 [2] 52 18 [2] 7c 3a [2] 68 21 [2] 67 3b [2] 79 26 [2] 7b 27 [2] 60 21 [2] 7c 26 [2] 60 09 }

  condition:
    any of them
}