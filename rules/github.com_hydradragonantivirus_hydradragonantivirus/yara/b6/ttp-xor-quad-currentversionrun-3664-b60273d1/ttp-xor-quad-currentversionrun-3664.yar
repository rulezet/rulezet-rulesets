rule TTP_XOR_QUAD_CurrentVersionRun_3664 {
  strings:
    $key_3664 = { 65 0b [2] 41 05 [2] 6a 29 [2] 44 0b [2] 50 10 [2] 5f 0a [2] 41 17 [2] 43 16 [2] 58 10 [2] 44 17 [2] 58 38 }

  condition:
    any of them
}