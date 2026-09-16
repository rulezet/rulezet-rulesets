rule TTP_XOR_QUAD_CurrentVersionRun_7d35 {
  strings:
    $key_7d35 = { 2e 5a [2] 0a 54 [2] 21 78 [2] 0f 5a [2] 1b 41 [2] 14 5b [2] 0a 46 [2] 08 47 [2] 13 41 [2] 0f 46 [2] 13 69 }

  condition:
    any of them
}