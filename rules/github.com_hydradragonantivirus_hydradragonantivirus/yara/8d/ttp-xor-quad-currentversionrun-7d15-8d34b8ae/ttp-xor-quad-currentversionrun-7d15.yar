rule TTP_XOR_QUAD_CurrentVersionRun_7d15 {
  strings:
    $key_7d15 = { 2e 7a [2] 0a 74 [2] 21 58 [2] 0f 7a [2] 1b 61 [2] 14 7b [2] 0a 66 [2] 08 67 [2] 13 61 [2] 0f 66 [2] 13 49 }

  condition:
    any of them
}