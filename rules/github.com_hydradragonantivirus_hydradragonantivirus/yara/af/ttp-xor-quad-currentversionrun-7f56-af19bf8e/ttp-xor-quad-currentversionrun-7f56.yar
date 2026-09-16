rule TTP_XOR_QUAD_CurrentVersionRun_7f56 {
  strings:
    $key_7f56 = { 2c 39 [2] 08 37 [2] 23 1b [2] 0d 39 [2] 19 22 [2] 16 38 [2] 08 25 [2] 0a 24 [2] 11 22 [2] 0d 25 [2] 11 0a }

  condition:
    any of them
}