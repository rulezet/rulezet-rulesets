rule TTP_XOR_QUAD_CurrentVersionRun_7356 {
  strings:
    $key_7356 = { 20 39 [2] 04 37 [2] 2f 1b [2] 01 39 [2] 15 22 [2] 1a 38 [2] 04 25 [2] 06 24 [2] 1d 22 [2] 01 25 [2] 1d 0a }

  condition:
    any of them
}