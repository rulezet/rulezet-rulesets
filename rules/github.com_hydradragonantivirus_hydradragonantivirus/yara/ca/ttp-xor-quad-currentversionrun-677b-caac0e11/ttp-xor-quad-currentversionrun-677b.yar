rule TTP_XOR_QUAD_CurrentVersionRun_677b {
  strings:
    $key_677b = { 34 14 [2] 10 1a [2] 3b 36 [2] 15 14 [2] 01 0f [2] 0e 15 [2] 10 08 [2] 12 09 [2] 09 0f [2] 15 08 [2] 09 27 }

  condition:
    any of them
}