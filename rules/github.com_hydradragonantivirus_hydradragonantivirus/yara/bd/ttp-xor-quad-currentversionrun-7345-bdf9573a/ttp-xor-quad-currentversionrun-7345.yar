rule TTP_XOR_QUAD_CurrentVersionRun_7345 {
  strings:
    $key_7345 = { 20 2a [2] 04 24 [2] 2f 08 [2] 01 2a [2] 15 31 [2] 1a 2b [2] 04 36 [2] 06 37 [2] 1d 31 [2] 01 36 [2] 1d 19 }

  condition:
    any of them
}