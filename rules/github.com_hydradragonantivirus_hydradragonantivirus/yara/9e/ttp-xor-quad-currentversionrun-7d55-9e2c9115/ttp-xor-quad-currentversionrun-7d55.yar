rule TTP_XOR_QUAD_CurrentVersionRun_7d55 {
  strings:
    $key_7d55 = { 2e 3a [2] 0a 34 [2] 21 18 [2] 0f 3a [2] 1b 21 [2] 14 3b [2] 0a 26 [2] 08 27 [2] 13 21 [2] 0f 26 [2] 13 09 }

  condition:
    any of them
}