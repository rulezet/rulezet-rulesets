rule TTP_XOR_QUAD_CurrentVersionRun_4745 {
  strings:
    $key_4745 = { 14 2a [2] 30 24 [2] 1b 08 [2] 35 2a [2] 21 31 [2] 2e 2b [2] 30 36 [2] 32 37 [2] 29 31 [2] 35 36 [2] 29 19 }

  condition:
    any of them
}