rule TTP_XOR_QUAD_CurrentVersionRun_3e55 {
  strings:
    $key_3e55 = { 6d 3a [2] 49 34 [2] 62 18 [2] 4c 3a [2] 58 21 [2] 57 3b [2] 49 26 [2] 4b 27 [2] 50 21 [2] 4c 26 [2] 50 09 }

  condition:
    any of them
}