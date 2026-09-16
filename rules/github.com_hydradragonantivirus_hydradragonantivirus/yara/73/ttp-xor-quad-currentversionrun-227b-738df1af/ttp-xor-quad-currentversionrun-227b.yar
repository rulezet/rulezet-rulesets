rule TTP_XOR_QUAD_CurrentVersionRun_227b {
  strings:
    $key_227b = { 71 14 [2] 55 1a [2] 7e 36 [2] 50 14 [2] 44 0f [2] 4b 15 [2] 55 08 [2] 57 09 [2] 4c 0f [2] 50 08 [2] 4c 27 }

  condition:
    any of them
}