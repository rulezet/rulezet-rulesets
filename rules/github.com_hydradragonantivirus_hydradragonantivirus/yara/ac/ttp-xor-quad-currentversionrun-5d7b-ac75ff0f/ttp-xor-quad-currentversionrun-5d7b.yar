rule TTP_XOR_QUAD_CurrentVersionRun_5d7b {
  strings:
    $key_5d7b = { 0e 14 [2] 2a 1a [2] 01 36 [2] 2f 14 [2] 3b 0f [2] 34 15 [2] 2a 08 [2] 28 09 [2] 33 0f [2] 2f 08 [2] 33 27 }

  condition:
    any of them
}