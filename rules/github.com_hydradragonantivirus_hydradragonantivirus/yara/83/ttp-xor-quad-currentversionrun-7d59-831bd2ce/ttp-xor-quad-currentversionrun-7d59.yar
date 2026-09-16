rule TTP_XOR_QUAD_CurrentVersionRun_7d59 {
  strings:
    $key_7d59 = { 2e 36 [2] 0a 38 [2] 21 14 [2] 0f 36 [2] 1b 2d [2] 14 37 [2] 0a 2a [2] 08 2b [2] 13 2d [2] 0f 2a [2] 13 05 }

  condition:
    any of them
}