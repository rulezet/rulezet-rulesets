rule TTP_XOR_QUAD_CurrentVersionRun_4768 {
  strings:
    $key_4768 = { 14 07 [2] 30 09 [2] 1b 25 [2] 35 07 [2] 21 1c [2] 2e 06 [2] 30 1b [2] 32 1a [2] 29 1c [2] 35 1b [2] 29 34 }

  condition:
    any of them
}