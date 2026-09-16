rule TTP_XOR_QUAD_CurrentVersionRun_7c7b {
  strings:
    $key_7c7b = { 2f 14 [2] 0b 1a [2] 20 36 [2] 0e 14 [2] 1a 0f [2] 15 15 [2] 0b 08 [2] 09 09 [2] 12 0f [2] 0e 08 [2] 12 27 }

  condition:
    any of them
}