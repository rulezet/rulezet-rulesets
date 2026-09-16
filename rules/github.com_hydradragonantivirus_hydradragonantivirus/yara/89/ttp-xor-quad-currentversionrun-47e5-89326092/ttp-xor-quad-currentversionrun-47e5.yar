rule TTP_XOR_QUAD_CurrentVersionRun_47e5 {
  strings:
    $key_47e5 = { 14 8a [2] 30 84 [2] 1b a8 [2] 35 8a [2] 21 91 [2] 2e 8b [2] 30 96 [2] 32 97 [2] 29 91 [2] 35 96 [2] 29 b9 }

  condition:
    any of them
}