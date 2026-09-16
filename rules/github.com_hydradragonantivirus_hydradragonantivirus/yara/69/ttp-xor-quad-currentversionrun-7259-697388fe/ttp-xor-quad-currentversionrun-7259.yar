rule TTP_XOR_QUAD_CurrentVersionRun_7259 {
  strings:
    $key_7259 = { 21 36 [2] 05 38 [2] 2e 14 [2] 00 36 [2] 14 2d [2] 1b 37 [2] 05 2a [2] 07 2b [2] 1c 2d [2] 00 2a [2] 1c 05 }

  condition:
    any of them
}