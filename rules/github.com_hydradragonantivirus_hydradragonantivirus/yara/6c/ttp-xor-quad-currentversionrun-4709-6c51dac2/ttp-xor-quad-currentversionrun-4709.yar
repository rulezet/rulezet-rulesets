rule TTP_XOR_QUAD_CurrentVersionRun_4709 {
  strings:
    $key_4709 = { 14 66 [2] 30 68 [2] 1b 44 [2] 35 66 [2] 21 7d [2] 2e 67 [2] 30 7a [2] 32 7b [2] 29 7d [2] 35 7a [2] 29 55 }

  condition:
    any of them
}