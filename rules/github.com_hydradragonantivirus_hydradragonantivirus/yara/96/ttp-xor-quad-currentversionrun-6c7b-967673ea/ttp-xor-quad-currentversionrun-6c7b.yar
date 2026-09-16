rule TTP_XOR_QUAD_CurrentVersionRun_6c7b {
  strings:
    $key_6c7b = { 3f 14 [2] 1b 1a [2] 30 36 [2] 1e 14 [2] 0a 0f [2] 05 15 [2] 1b 08 [2] 19 09 [2] 02 0f [2] 1e 08 [2] 02 27 }

  condition:
    any of them
}