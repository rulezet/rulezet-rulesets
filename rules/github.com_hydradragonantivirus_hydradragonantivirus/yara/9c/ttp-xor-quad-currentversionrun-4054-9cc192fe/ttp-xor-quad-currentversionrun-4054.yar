rule TTP_XOR_QUAD_CurrentVersionRun_4054 {
  strings:
    $key_4054 = { 13 3b [2] 37 35 [2] 1c 19 [2] 32 3b [2] 26 20 [2] 29 3a [2] 37 27 [2] 35 26 [2] 2e 20 [2] 32 27 [2] 2e 08 }

  condition:
    any of them
}