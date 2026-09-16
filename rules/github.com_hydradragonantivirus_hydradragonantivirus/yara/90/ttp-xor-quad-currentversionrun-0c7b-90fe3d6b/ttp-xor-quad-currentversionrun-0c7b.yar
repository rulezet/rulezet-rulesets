rule TTP_XOR_QUAD_CurrentVersionRun_0c7b {
  strings:
    $key_0c7b = { 5f 14 [2] 7b 1a [2] 50 36 [2] 7e 14 [2] 6a 0f [2] 65 15 [2] 7b 08 [2] 79 09 [2] 62 0f [2] 7e 08 [2] 62 27 }

  condition:
    any of them
}