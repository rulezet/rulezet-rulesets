rule TTP_XOR_QUAD_CurrentVersionRun_2f56 {
  strings:
    $key_2f56 = { 7c 39 [2] 58 37 [2] 73 1b [2] 5d 39 [2] 49 22 [2] 46 38 [2] 58 25 [2] 5a 24 [2] 41 22 [2] 5d 25 [2] 41 0a }

  condition:
    any of them
}