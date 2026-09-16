rule TTP_XOR_QUAD_CurrentVersionRun_7d6b {
  strings:
    $key_7d6b = { 2e 04 [2] 0a 0a [2] 21 26 [2] 0f 04 [2] 1b 1f [2] 14 05 [2] 0a 18 [2] 08 19 [2] 13 1f [2] 0f 18 [2] 13 37 }

  condition:
    any of them
}