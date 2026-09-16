rule TTP_XOR_QUAD_CurrentVersionRun_4744 {
  strings:
    $key_4744 = { 14 2b [2] 30 25 [2] 1b 09 [2] 35 2b [2] 21 30 [2] 2e 2a [2] 30 37 [2] 32 36 [2] 29 30 [2] 35 37 [2] 29 18 }

  condition:
    any of them
}