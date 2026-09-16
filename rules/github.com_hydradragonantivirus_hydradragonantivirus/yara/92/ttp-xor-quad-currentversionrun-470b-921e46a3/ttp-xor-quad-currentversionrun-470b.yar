rule TTP_XOR_QUAD_CurrentVersionRun_470b {
  strings:
    $key_470b = { 14 64 [2] 30 6a [2] 1b 46 [2] 35 64 [2] 21 7f [2] 2e 65 [2] 30 78 [2] 32 79 [2] 29 7f [2] 35 78 [2] 29 57 }

  condition:
    any of them
}