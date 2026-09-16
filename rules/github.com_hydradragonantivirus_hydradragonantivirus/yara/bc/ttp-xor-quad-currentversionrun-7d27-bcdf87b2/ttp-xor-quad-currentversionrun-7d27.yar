rule TTP_XOR_QUAD_CurrentVersionRun_7d27 {
  strings:
    $key_7d27 = { 2e 48 [2] 0a 46 [2] 21 6a [2] 0f 48 [2] 1b 53 [2] 14 49 [2] 0a 54 [2] 08 55 [2] 13 53 [2] 0f 54 [2] 13 7b }

  condition:
    any of them
}