rule TTP_XOR_QUAD_CurrentVersionRun_4759 {
  strings:
    $key_4759 = { 14 36 [2] 30 38 [2] 1b 14 [2] 35 36 [2] 21 2d [2] 2e 37 [2] 30 2a [2] 32 2b [2] 29 2d [2] 35 2a [2] 29 05 }

  condition:
    any of them
}