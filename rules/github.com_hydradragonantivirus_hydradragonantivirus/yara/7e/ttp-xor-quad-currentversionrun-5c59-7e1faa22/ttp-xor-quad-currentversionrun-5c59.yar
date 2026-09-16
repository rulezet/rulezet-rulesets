rule TTP_XOR_QUAD_CurrentVersionRun_5c59 {
  strings:
    $key_5c59 = { 0f 36 [2] 2b 38 [2] 00 14 [2] 2e 36 [2] 3a 2d [2] 35 37 [2] 2b 2a [2] 29 2b [2] 32 2d [2] 2e 2a [2] 32 05 }

  condition:
    any of them
}