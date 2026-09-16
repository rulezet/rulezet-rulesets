rule TTP_XOR_QUAD_CurrentVersionRun_4724 {
  strings:
    $key_4724 = { 14 4b [2] 30 45 [2] 1b 69 [2] 35 4b [2] 21 50 [2] 2e 4a [2] 30 57 [2] 32 56 [2] 29 50 [2] 35 57 [2] 29 78 }

  condition:
    any of them
}