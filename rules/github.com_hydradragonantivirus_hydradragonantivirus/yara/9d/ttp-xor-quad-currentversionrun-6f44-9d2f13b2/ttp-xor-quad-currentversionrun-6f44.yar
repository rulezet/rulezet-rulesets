rule TTP_XOR_QUAD_CurrentVersionRun_6f44 {
  strings:
    $key_6f44 = { 3c 2b [2] 18 25 [2] 33 09 [2] 1d 2b [2] 09 30 [2] 06 2a [2] 18 37 [2] 1a 36 [2] 01 30 [2] 1d 37 [2] 01 18 }

  condition:
    any of them
}