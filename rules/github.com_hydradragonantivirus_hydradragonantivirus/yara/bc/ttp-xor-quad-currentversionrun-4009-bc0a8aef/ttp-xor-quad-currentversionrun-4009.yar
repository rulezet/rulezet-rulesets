rule TTP_XOR_QUAD_CurrentVersionRun_4009 {
  strings:
    $key_4009 = { 13 66 [2] 37 68 [2] 1c 44 [2] 32 66 [2] 26 7d [2] 29 67 [2] 37 7a [2] 35 7b [2] 2e 7d [2] 32 7a [2] 2e 55 }

  condition:
    any of them
}