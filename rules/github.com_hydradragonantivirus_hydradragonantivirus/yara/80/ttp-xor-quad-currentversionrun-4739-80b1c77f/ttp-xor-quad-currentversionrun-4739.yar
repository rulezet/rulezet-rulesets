rule TTP_XOR_QUAD_CurrentVersionRun_4739 {
  strings:
    $key_4739 = { 14 56 [2] 30 58 [2] 1b 74 [2] 35 56 [2] 21 4d [2] 2e 57 [2] 30 4a [2] 32 4b [2] 29 4d [2] 35 4a [2] 29 65 }

  condition:
    any of them
}