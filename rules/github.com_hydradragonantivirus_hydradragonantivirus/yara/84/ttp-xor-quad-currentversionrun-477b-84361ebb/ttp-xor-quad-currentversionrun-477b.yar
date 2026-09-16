rule TTP_XOR_QUAD_CurrentVersionRun_477b {
  strings:
    $key_477b = { 14 14 [2] 30 1a [2] 1b 36 [2] 35 14 [2] 21 0f [2] 2e 15 [2] 30 08 [2] 32 09 [2] 29 0f [2] 35 08 [2] 29 27 }

  condition:
    any of them
}