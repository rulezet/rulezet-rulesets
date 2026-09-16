rule TTP_XOR_QUAD_CurrentVersionRun_7d7b {
  strings:
    $key_7d7b = { 2e 14 [2] 0a 1a [2] 21 36 [2] 0f 14 [2] 1b 0f [2] 14 15 [2] 0a 08 [2] 08 09 [2] 13 0f [2] 0f 08 [2] 13 27 }

  condition:
    any of them
}