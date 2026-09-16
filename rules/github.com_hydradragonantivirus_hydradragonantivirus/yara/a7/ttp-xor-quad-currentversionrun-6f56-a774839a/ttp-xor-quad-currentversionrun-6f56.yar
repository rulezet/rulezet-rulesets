rule TTP_XOR_QUAD_CurrentVersionRun_6f56 {
  strings:
    $key_6f56 = { 3c 39 [2] 18 37 [2] 33 1b [2] 1d 39 [2] 09 22 [2] 06 38 [2] 18 25 [2] 1a 24 [2] 01 22 [2] 1d 25 [2] 01 0a }

  condition:
    any of them
}