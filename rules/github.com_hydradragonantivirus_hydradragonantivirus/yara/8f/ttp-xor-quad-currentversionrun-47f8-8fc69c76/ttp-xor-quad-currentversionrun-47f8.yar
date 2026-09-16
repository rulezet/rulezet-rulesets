rule TTP_XOR_QUAD_CurrentVersionRun_47f8 {
  strings:
    $key_47f8 = { 14 97 [2] 30 99 [2] 1b b5 [2] 35 97 [2] 21 8c [2] 2e 96 [2] 30 8b [2] 32 8a [2] 29 8c [2] 35 8b [2] 29 a4 }

  condition:
    any of them
}