rule TTP_XOR_QUAD_CurrentVersionRun_567b {
  strings:
    $key_567b = { 05 14 [2] 21 1a [2] 0a 36 [2] 24 14 [2] 30 0f [2] 3f 15 [2] 21 08 [2] 23 09 [2] 38 0f [2] 24 08 [2] 38 27 }

  condition:
    any of them
}