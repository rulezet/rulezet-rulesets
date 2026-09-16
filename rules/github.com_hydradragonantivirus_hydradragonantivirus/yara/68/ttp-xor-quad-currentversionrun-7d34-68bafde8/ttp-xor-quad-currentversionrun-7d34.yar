rule TTP_XOR_QUAD_CurrentVersionRun_7d34 {
  strings:
    $key_7d34 = { 2e 5b [2] 0a 55 [2] 21 79 [2] 0f 5b [2] 1b 40 [2] 14 5a [2] 0a 47 [2] 08 46 [2] 13 40 [2] 0f 47 [2] 13 68 }

  condition:
    any of them
}