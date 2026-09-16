rule TTP_XOR_QUAD_CurrentVersionRun_4044 {
  strings:
    $key_4044 = { 13 2b [2] 37 25 [2] 1c 09 [2] 32 2b [2] 26 30 [2] 29 2a [2] 37 37 [2] 35 36 [2] 2e 30 [2] 32 37 [2] 2e 18 }

  condition:
    any of them
}