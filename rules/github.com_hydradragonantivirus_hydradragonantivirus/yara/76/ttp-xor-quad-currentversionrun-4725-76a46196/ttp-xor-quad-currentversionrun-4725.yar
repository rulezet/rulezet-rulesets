rule TTP_XOR_QUAD_CurrentVersionRun_4725 {
  strings:
    $key_4725 = { 14 4a [2] 30 44 [2] 1b 68 [2] 35 4a [2] 21 51 [2] 2e 4b [2] 30 56 [2] 32 57 [2] 29 51 [2] 35 56 [2] 29 79 }

  condition:
    any of them
}